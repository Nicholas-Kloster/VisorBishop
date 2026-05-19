package fingerprint

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/Nicholas-Kloster/VisorBishop/internal/probe"
)

// trimTarget strips a trailing slash from the target URL so that path
// concatenation (target+"/api/config") never produces a double slash.
// This is called once per Probe invocation — not modified on the Finding.
func trimTarget(t string) string {
	return strings.TrimRight(t, "/")
}

// OpenWebUIProber detects Open WebUI self-hosted instances.
//
// Open WebUI is an extensible LLM chat frontend that wraps Ollama, OpenAI,
// and other backends. Auth is opt-in: the admin can disable login entirely
// (AUTH_DISABLED — any visitor becomes an admin) or leave self-registration
// open (SIGNUP_OPEN — anyone can register and immediately access all models).
// Both states represent account-takeover primitives at institutions deploying
// this in the survey period.
//
// Auth posture is read directly from /api/config — a single unauth probe that
// discloses the full feature flag surface without any credential.
//
// Reference: github.com/open-webui/open-webui
// Real-world anchors: Duke vcm-51699 (v0.7.2, signup-open),
//
//	UCLA ai.idre.ucla.edu:3000 (v0.6.5, signup-open per earlier survey),
//	DePaul 140.192.183.141 (v0.4.7, auth-on-default).
type OpenWebUIProber struct{}

func (p OpenWebUIProber) ID() Platform { return OpenWebUI }

// openWebUIConfig mirrors the JSON structure of Open WebUI /api/config.
// Fields added/removed across versions; use pointers so absent fields unmarshal
// as nil rather than false.
type openWebUIConfig struct {
	Status  bool   `json:"status"`
	Name    string `json:"name"`
	Version string `json:"version"`
	OAuth   struct {
		Providers map[string]string `json:"providers"`
	} `json:"oauth"`
	Features struct {
		Auth           *bool `json:"auth"`
		EnableSignup   *bool `json:"enable_signup"`
		EnableLDAP     *bool `json:"enable_ldap"`
		EnableAPIKeys  *bool `json:"enable_api_keys"` // ≥v0.4
		EnableAPIKey   *bool `json:"enable_api_key"`  // <v0.4 spelling variant
		EnableWebSocket *bool `json:"enable_websocket"`
	} `json:"features"`
}

func (p OpenWebUIProber) Probe(ctx context.Context, client *http.Client, target, hostname string) Finding {
	base := trimTarget(target) // prevents double-slash when target has trailing /
	f := Finding{
		Target:   target,
		Hostname: hostname,
		Platform: OpenWebUI,
		Auth:     AuthUnknown,
		Severity: SevNone,
	}

	indicators := map[string]interface{}{}

	// Step 1: probe /api/config — primary identity + auth posture in one shot.
	r := probe.Get(ctx, client, base+"/api/config", hostname, 8192)
	f.LatencyMS = r.LatencyMS

	var cfg openWebUIConfig
	if r.Err == nil && r.Status == 200 {
		if err := json.Unmarshal(r.Body, &cfg); err == nil && cfg.Name == "Open WebUI" {
			f.Confirmed = true
			f.Version = cfg.Version
		}
	}

	// Step 2: fall back to /manifest.json if /api/config missed.
	if !f.Confirmed {
		rm := probe.Get(ctx, client, base+"/manifest.json", hostname, 2048)
		if rm.Err == nil && rm.Status == 200 {
			var manifest struct {
				Name string `json:"name"`
			}
			if err := json.Unmarshal(rm.Body, &manifest); err == nil && manifest.Name == "Open WebUI" {
				f.Confirmed = true
				// Version not available from manifest — leave empty.
			}
		}
	}

	if !f.Confirmed {
		return f
	}

	// Step 3: classify auth posture from the /api/config feature flags.
	// Only meaningful if /api/config was the confirming probe (cfg is populated).
	if cfg.Name == "Open WebUI" {
		authEnabled := cfg.Features.Auth
		signupEnabled := cfg.Features.EnableSignup

		switch {
		case authEnabled != nil && !*authEnabled:
			// features.auth: false — no login screen at all; every visitor gets
			// full access.  This is the highest-severity state.
			f.Auth = AuthOpen
			f.Severity = SevCritical
			f.Notes = append(f.Notes, "CRITICAL: auth disabled (features.auth=false) — unauthenticated full access")
			indicators["auth_disabled"] = true

		case authEnabled != nil && *authEnabled &&
			signupEnabled != nil && *signupEnabled:
			// Auth is on but self-registration is open — anyone can create an
			// account and immediately access all models.
			f.Auth = AuthSignupOpen
			f.Severity = SevCritical
			f.Notes = append(f.Notes, "CRITICAL: open self-registration (features.enable_signup=true) — account-takeover primitive")
			indicators["signup_open"] = true

		case authEnabled != nil && *authEnabled:
			// Auth on, signup closed — normal locked-down state.
			f.Auth = AuthProtected
			f.Severity = SevInfo

		default:
			f.Auth = AuthUnknown
		}

		// Surface LDAP config exposure.
		if cfg.Features.EnableLDAP != nil && *cfg.Features.EnableLDAP {
			indicators["ldap_enabled"] = true
			f.Notes = append(f.Notes, "LDAP authentication configured")
		}

		// Surface API-key config (either spelling).
		apiKeysOn := (cfg.Features.EnableAPIKeys != nil && *cfg.Features.EnableAPIKeys) ||
			(cfg.Features.EnableAPIKey != nil && *cfg.Features.EnableAPIKey)
		if apiKeysOn {
			indicators["api_keys_enabled"] = true
		}

		// Surface OAuth providers (e.g. {"oidc": "Descope"} → institution SSO config).
		if len(cfg.OAuth.Providers) > 0 {
			providers := []string{}
			for k := range cfg.OAuth.Providers {
				providers = append(providers, k)
			}
			indicators["oauth_providers"] = providers
		}
	}

	if len(indicators) > 0 {
		f.Indicators = indicators
	}

	// Step 4: if version is still unknown, try /api/version.
	if f.Version == "" {
		rv := probe.Get(ctx, client, base+"/api/version", hostname, 256)
		if rv.Err == nil && rv.Status == 200 {
			body := string(rv.Body)
			if i := strings.Index(body, `"version":"`); i >= 0 {
				rest := body[i+11:]
				if j := strings.Index(rest, `"`); j > 0 {
					f.Version = rest[:j]
				}
			}
		}
	}

	return f
}
