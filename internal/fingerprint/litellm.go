package fingerprint

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/Nicholas-Kloster/VisorBishop/internal/probe"
)

// LiteLLMProber detects LiteLLM Proxy self-hosted instances.
//
// LiteLLM is a different tier than the observability platforms — it's an
// LLM gateway/proxy that stores provider API keys and serves an
// OpenAI-compatible API. Authentication is opt-in via the LITELLM_MASTER_KEY
// env var; when not set, /v1/models and /v1/chat/completions are reachable
// without authentication, which is a CRITICAL LLMjacking primitive
// (attacker burns operator's LLM budget by sending prompts through the
// proxy).
//
// Reference: github.com/BerriAI/litellm
type LiteLLMProber struct{}

func (p LiteLLMProber) ID() Platform { return LiteLLM }

func (p LiteLLMProber) Probe(ctx context.Context, client *http.Client, target, hostname string) Finding {
	base := trimTarget(target) // prevents double-slash when target has trailing /
	f := Finding{
		Target:   target,
		Hostname: hostname,
		Platform: LiteLLM,
		Auth:     AuthUnknown,
		Severity: SevNone,
	}

	// Step 1: confirm LiteLLM via the Swagger root or models endpoint
	r := probe.Get(ctx, client, base+"/v1/models", hostname, 8192)
	f.LatencyMS = r.LatencyMS
	if r.Err != nil {
		return f
	}

	indicators := map[string]interface{}{}

	// LiteLLM-specific markers we need before flagging confirmed:
	//   * /openapi.json info.title == "LiteLLM API"  (most reliable — spec-mandated string)
	//   * Root HTML contains "LiteLLM API" in the title (Swagger UI fallback)
	//   * /health/readiness JSON has litellm_version field
	//   * /.well-known/litellm-ui-config returns proxy_base_url JSON
	// /v1/models matching alone is too loose — every OpenAI-compatible
	// proxy serves the same shape (vLLM, Ollama proxy, OpenRouter, etc.).
	litellmConfirmed := false

	// Primary: /openapi.json title (anchors on spec-mandated string, not HTML)
	roapi := probe.Get(ctx, client, base+"/openapi.json", hostname, 4096)
	if roapi.Status == 200 && strings.Contains(string(roapi.Body), `"LiteLLM API"`) {
		litellmConfirmed = true
		// Extract version from openapi info.version while we have the body.
		body := string(roapi.Body)
		if i := strings.Index(body, `"version":"`); i > 0 {
			rest := body[i+11:]
			if j := strings.Index(rest, `"`); j > 0 {
				f.Version = rest[:j]
			}
		}
	}

	// Fallback: /health/readiness litellm_version field
	if !litellmConfirmed {
		rhr := probe.Get(ctx, client, base+"/health/readiness", hostname, 1024)
		if rhr.Status == 200 && strings.Contains(string(rhr.Body), "litellm_version") {
			litellmConfirmed = true
			body := string(rhr.Body)
			if i := strings.Index(body, `"litellm_version":"`); i >= 0 {
				rest := body[i+19:]
				if j := strings.Index(rest, `"`); j > 0 {
					f.Version = rest[:j]
				}
			}
		}
	}

	// Fallback: root HTML Swagger title
	if !litellmConfirmed {
		ru := probe.Get(ctx, client, base+"/", hostname, 4096)
		if ru.Status == 200 && strings.Contains(string(ru.Body), "LiteLLM API") {
			litellmConfirmed = true
		}
	}

	// Fallback: well-known config endpoint
	if !litellmConfirmed {
		ruc := probe.Get(ctx, client, base+"/.well-known/litellm-ui-config", hostname, 512)
		if ruc.Status == 200 && strings.Contains(string(ruc.Body), "proxy_base_url") {
			litellmConfirmed = true
			indicators["litellm_ui_config_exposed"] = true
		}
	}

	if !litellmConfirmed {
		return f
	}

	// Now interpret /v1/models result given confirmed LiteLLM identity
	switch {
	case r.Status == 200:
		var modelsResp struct {
			Data []struct {
				ID      string `json:"id"`
				Object  string `json:"object"`
				Created int64  `json:"created"`
			} `json:"data"`
		}
		if err := json.Unmarshal(r.Body, &modelsResp); err == nil && len(modelsResp.Data) > 0 {
			f.Confirmed = true
			f.Auth = AuthOpen
			f.Severity = SevCritical
			modelIDs := []string{}
			for _, m := range modelsResp.Data {
				modelIDs = append(modelIDs, m.ID)
			}
			indicators["model_count"] = len(modelIDs)
			if len(modelIDs) <= 20 {
				indicators["model_ids"] = modelIDs
			} else {
				indicators["model_ids_sample"] = modelIDs[:20]
			}
			f.Notes = append(f.Notes, "CRITICAL: /v1/models returns model catalog without authentication (LITELLM_MASTER_KEY not set)")
			f.Notes = append(f.Notes, "/v1/chat/completions likely also unauth — LLMjacking primitive")
		}
	case r.Status == 401:
		f.Confirmed = true
		f.Auth = AuthProtected
		f.Severity = SevInfo
	default:
		// Confirmed as LiteLLM but unusual auth state
		f.Confirmed = true
		f.Auth = AuthUnknown
		f.Severity = SevInfo
	}

	// /public/providers — unauth provider list. Present in LiteLLM ≥1.x; a 200
	// response leaks the full provider roster (anthropic, openai, bedrock, etc.)
	// without auth. Not a credential leak but discloses the proxy's backend config.
	// Severity: HIGH when auth is otherwise intact; CRITICAL when stacked on AuthOpen.
	rpp := probe.Get(ctx, client, base+"/public/providers", hostname, 16384)
	if rpp.Status == 200 && len(rpp.Body) > 2 {
		indicators["public_providers_exposed"] = true
		// Count entries — the body is a JSON array of provider-name strings.
		providerCount := strings.Count(string(rpp.Body), `"`)
		if providerCount > 0 {
			indicators["provider_count_approx"] = providerCount / 2 // each name = 2 quotes
		}
		if f.Auth == AuthProtected || f.Auth == AuthUnknown {
			// Auth is otherwise intact; bump to info-leak tier.
			f.Auth = AuthPublicAPI
			f.Severity = SevHigh
			f.Notes = append(f.Notes, "HIGH: /public/providers returns full provider list without authentication (backend config disclosure)")
		}
		// If already AuthOpen/SevCritical, don't downgrade — just record the indicator.
	}

	if f.Confirmed && len(indicators) > 0 {
		f.Indicators = indicators
	}
	return f
}
