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
	f := Finding{
		Target:   target,
		Hostname: hostname,
		Platform: LiteLLM,
		Auth:     AuthUnknown,
		Severity: SevNone,
	}

	// Step 1: confirm LiteLLM via the Swagger root or models endpoint
	r := probe.Get(ctx, client, target+"/v1/models", hostname, 8192)
	f.LatencyMS = r.LatencyMS
	if r.Err != nil {
		return f
	}

	indicators := map[string]interface{}{}

	// LiteLLM-specific markers we need before flagging confirmed:
	//   * Root HTML contains "LiteLLM API" in the title (Swagger UI)
	//   * /.well-known/litellm-ui-config returns proxy_base_url JSON
	// /v1/models matching alone is too loose — every OpenAI-compatible
	// proxy serves the same shape (vLLM, Ollama proxy, OpenRouter, etc.).
	litellmConfirmed := false
	ru := probe.Get(ctx, client, target+"/", hostname, 4096)
	if ru.Status == 200 && strings.Contains(string(ru.Body), "LiteLLM API") {
		litellmConfirmed = true
	}
	if !litellmConfirmed {
		// Try the well-known config endpoint
		ruc := probe.Get(ctx, client, target+"/.well-known/litellm-ui-config", hostname, 512)
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

	// Pull OpenAPI version regardless of auth state
	rv := probe.Get(ctx, client, target+"/openapi.json", hostname, 4096)
	if rv.Status == 200 {
		body := string(rv.Body)
		if i := strings.Index(body, `"version":"`); i > 0 {
			rest := body[i+11:]
			if j := strings.Index(rest, `"`); j > 0 {
				f.Version = rest[:j]
			}
		}
	}

	if f.Confirmed && len(indicators) > 0 {
		f.Indicators = indicators
	}
	return f
}
