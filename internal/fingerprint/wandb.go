package fingerprint

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/Nicholas-Kloster/VisorBishop/internal/probe"
)

// WandbProber detects Weights & Biases self-hosted ("local server") instances.
//
// W&B is primarily SaaS at wandb.ai, but offers a self-hosted "Server"
// product for on-prem deployments. Self-hosts run an internal Apollo
// GraphQL API at /graphql. The viewer query exposes the current
// authenticated user — when no auth is set up, it returns the anonymous
// viewer record (or 401 if auth is enforced).
//
// Self-host data class includes training runs, sweeps, artifacts,
// model checkpoints, system metrics, and reports — all the prompt/
// response/parameter data attached to ML experiments.
//
// Reference: github.com/wandb/wandb · docs.wandb.ai/guides/hosting
type WandbProber struct{}

func (p WandbProber) ID() Platform { return Wandb }

func (p WandbProber) Probe(ctx context.Context, client *http.Client, target, hostname string) Finding {
	f := Finding{
		Target:   target,
		Hostname: hostname,
		Platform: Wandb,
		Auth:     AuthUnknown,
		Severity: SevNone,
	}

	// Step 1: confirm W&B via the SPA root markers.
	// "<title>Weights &amp; Biases</title>" + the /env.js bootstrap script
	// + Sentry script are the specific local-server fingerprints.
	ru := probe.Get(ctx, client, target+"/", hostname, 8192)
	f.LatencyMS = ru.LatencyMS
	if ru.Err != nil {
		return f
	}
	body := string(ru.Body)
	wandbSPA := strings.Contains(body, "<title>Weights &amp; Biases</title>") &&
		(strings.Contains(body, "/env.js") || strings.Contains(body, "data-dark-mode") ||
			strings.Contains(body, "raven.min.js"))
	if !wandbSPA {
		return f
	}

	indicators := map[string]interface{}{
		"spa_root_match": true,
	}

	// Step 2: probe /env.js for build-time config (often leaks auth mode,
	// instance type, organization name on self-hosts).
	re := probe.Get(ctx, client, target+"/env.js", hostname, 4096)
	if re.Status == 200 {
		envBody := string(re.Body)
		if len(envBody) > 0 && len(envBody) < 4000 {
			indicators["env_js_present"] = true
			// Pull out common signals
			if strings.Contains(envBody, "AUTH_STATELESS") || strings.Contains(envBody, "stateless") {
				indicators["auth_mode_hint"] = "stateless"
			}
			if strings.Contains(envBody, "ANONYMOUS") || strings.Contains(envBody, "anonymous") {
				indicators["anonymous_mode_hint"] = true
			}
		}
	}

	// Step 3: probe /graphql with the viewer query for auth state.
	// W&B's Apollo server accepts GET introspection-style; we use POST
	// with a minimal viewer query.
	gqlBody := strings.NewReader(`{"query":"{ viewer { id username email } }"}`)
	req, err := http.NewRequestWithContext(ctx, "POST", target+"/graphql", gqlBody)
	if err == nil {
		req.Header.Set("Content-Type", "application/json")
		if hostname != "" {
			req.Host = hostname
		}
		resp, herr := client.Do(req)
		if herr == nil && resp != nil {
			defer resp.Body.Close()
			buf := make([]byte, 65536)
			n, _ := readAll(resp.Body, buf)
			switch {
			case resp.StatusCode == 200:
				var gqlResp struct {
					Data struct {
						Viewer *struct {
							ID       string `json:"id"`
							Username string `json:"username"`
							Email    string `json:"email"`
						} `json:"viewer"`
					} `json:"data"`
					Errors []struct {
						Message string `json:"message"`
					} `json:"errors"`
				}
				if jerr := json.Unmarshal(buf[:n], &gqlResp); jerr == nil {
					f.Confirmed = true
					if gqlResp.Data.Viewer == nil {
						// 200 with null viewer is the default response shape
						// for ANY W&B server (production or self-host) — the
						// resolver returns null when no auth context is
						// present. This confirms platform identity but does
						// NOT indicate data exposure: real W&B servers gate
						// entity / project / run data at the resolver level
						// behind the entity-name context (server returns
						// null for the data-layer queries).
						//
						// Treat as info-only platform confirmation.
						f.Auth = AuthInfoOnly
						f.Severity = SevInfo
						indicators["graphql_schema_reachable"] = true
						f.Notes = append(f.Notes,
							"GraphQL /graphql viewer query returns null (anonymous schema reachable) — data-layer queries still server-side-gated",
						)
					} else {
						// 200 with a populated viewer = real credential bypass
						// (server returns an authenticated identity to unauth
						// callers). This is rare and CRITICAL.
						f.Auth = AuthOpen
						f.Severity = SevCritical
						indicators["graphql_unauth_viewer_disclosed"] = true
						indicators["disclosed_viewer_username"] = gqlResp.Data.Viewer.Username
						if gqlResp.Data.Viewer.Email != "" {
							indicators["disclosed_viewer_email"] = gqlResp.Data.Viewer.Email
						}
						f.Notes = append(f.Notes,
							"CRITICAL: /graphql viewer query returns an authenticated identity without credentials",
						)
					}
				} else if len(gqlResp.Errors) > 0 {
					f.Confirmed = true
					f.Auth = AuthProtected
					f.Severity = SevInfo
					indicators["graphql_errors"] = true
				}
			case resp.StatusCode == 401 || resp.StatusCode == 403:
				f.Confirmed = true
				f.Auth = AuthProtected
				f.Severity = SevInfo
			default:
				f.Confirmed = true
				f.Auth = AuthUnknown
				f.Severity = SevInfo
				indicators["graphql_status"] = resp.StatusCode
			}
		}
	}

	// Step 4: probe /health for the server build version
	rh := probe.Get(ctx, client, target+"/health", hostname, 1024)
	if rh.Status == 200 {
		var health struct {
			Status  string `json:"status"`
			Version string `json:"version"`
			Build   string `json:"build"`
		}
		if jerr := json.Unmarshal(rh.Body, &health); jerr == nil && (health.Version != "" || health.Build != "") {
			if health.Version != "" {
				f.Version = health.Version
			} else if health.Build != "" {
				f.Version = health.Build
			}
		}
	}

	// Confirm by SPA alone if other probes were blocked
	if !f.Confirmed && wandbSPA {
		f.Confirmed = true
		f.Auth = AuthUnknown
		f.Severity = SevInfo
	}

	if f.Confirmed && len(indicators) > 0 {
		f.Indicators = indicators
	}
	return f
}

// readAll reads up to len(buf) bytes from r and returns the number of bytes
// read. Mirrors the behavior of probe.Get but for ad-hoc http.Response
// bodies (since the GraphQL probe needs an http.Request directly).
func readAll(r interface{ Read(p []byte) (n int, err error) }, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := r.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}
