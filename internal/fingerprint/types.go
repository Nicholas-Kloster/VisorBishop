// Package fingerprint defines the per-platform fingerprint contract for
// VisorBishop. Each platform fingerprint is a function that takes a target
// (URL + optional hostname for SNI) and returns a typed Finding describing
// whether the target is that platform, what version, and what auth-posture
// signals were observed.
package fingerprint

import (
	"context"
	"net/http"
)

// Platform is the canonical identifier for an observability platform.
type Platform string

const (
	PhoenixArize Platform = "arize-phoenix"
	Langfuse     Platform = "langfuse"
	Helicone     Platform = "helicone"
	LangSmith    Platform = "langsmith"
	Lunary       Platform = "lunary"
	OpenLIT      Platform = "openlit"
	Pezzo        Platform = "pezzo"
	OpikPlatform Platform = "comet-opik"
	AgentOps     Platform = "agentops"
	LiteLLM      Platform = "litellm"
	Argilla      Platform = "argilla"
	Promptfoo    Platform = "promptfoo"
	// iter-7 expansion: experiment-tracking tier
	MLflow Platform = "mlflow"
	Wandb  Platform = "wandb"
	Comet  Platform = "comet-ml"
	// iter-8 expansion: LLM-pipeline builders + ML orchestrators + product analytics
	Langflow Platform = "langflow"
	Dify     Platform = "dify"
	Kubeflow Platform = "kubeflow"
	PostHog  Platform = "posthog"
	Prefect  Platform = "prefect"
	Airflow  Platform = "airflow"
	// iter-9 expansion: LLM frontend + gateway tier (G5)
	OpenWebUI Platform = "open-webui"
)

// AllPlatforms returns the canonical list of platform identifiers that
// VisorBishop fingerprints. Useful for CLI flag parsing.
func AllPlatforms() []Platform {
	return []Platform{
		PhoenixArize, Langfuse, Helicone, LangSmith,
		Lunary, OpenLIT, Pezzo, OpikPlatform, AgentOps,
		LiteLLM, Argilla, Promptfoo,
		MLflow, Wandb, Comet,
		Langflow, Dify, Kubeflow, PostHog, Prefect, Airflow,
		OpenWebUI,
	}
}

// AuthState is the observed authentication posture for a platform endpoint.
type AuthState string

const (
	AuthUnknown     AuthState = "unknown"      // probe failed / inconclusive
	AuthOpen        AuthState = "unauth"       // primary API reachable without auth — CRITICAL
	AuthProtected   AuthState = "auth"         // returned 401/403 on protected route
	AuthInfoOnly    AuthState = "info-leak"    // platform has unauth-readable info endpoint but data is protected
	AuthMixed       AuthState = "mixed"        // some routes auth, some not
	AuthSignupOpen  AuthState = "signup-open"  // auth enabled but open self-registration — account-takeover risk
	AuthPublicAPI   AuthState = "public-api"   // public spec/provider endpoint exposed (no data, but leaks config)
)

// Severity is the standardized severity bucket assigned by the fingerprint.
type Severity string

const (
	SevCritical Severity = "critical"
	SevHigh     Severity = "high"
	SevMedium   Severity = "medium"
	SevLow      Severity = "low"
	SevInfo     Severity = "info"
	SevNone     Severity = "none"
)

// Finding is the canonical output of a single platform fingerprint against
// a single target. Findings are aggregated per-host in the final report.
type Finding struct {
	// Target is the URL probed.
	Target string `json:"target"`
	// Hostname is the SNI/Host header used (empty if probed by IP).
	Hostname string `json:"hostname,omitempty"`
	// Platform identifies the matched platform; empty if no platform matched.
	Platform Platform `json:"platform,omitempty"`
	// Confirmed is true if we are certain this is an instance of the platform
	// (vs a noise hit from a generic "platform name in HTML" match).
	Confirmed bool `json:"confirmed"`
	// Version is the platform version if extracted (e.g. "3.172.1" for Langfuse).
	Version string `json:"version,omitempty"`
	// GitSHA is the build commit if disclosed (e.g. LangSmith's /api/v1/info).
	GitSHA string `json:"git_sha,omitempty"`
	// LicenseExpiry is the license expiration if disclosed (LangSmith).
	LicenseExpiry string `json:"license_expiry,omitempty"`
	// Auth is the observed auth posture on the primary protected endpoint.
	Auth AuthState `json:"auth"`
	// Severity is the standardized bucket assigned by the fingerprint logic.
	Severity Severity `json:"severity"`
	// Indicators is a free-form map of platform-specific signals observed
	// (e.g. {"customer_name": "Grammarly", "playground_auth_bypass": true}).
	Indicators map[string]interface{} `json:"indicators,omitempty"`
	// Notes contains short human-readable observations.
	Notes []string `json:"notes,omitempty"`
	// LatencyMS is the wall time of the probe.
	LatencyMS int64 `json:"latency_ms,omitempty"`
}

// Prober is the interface every platform fingerprint must implement.
type Prober interface {
	// ID returns the platform identifier.
	ID() Platform
	// Probe runs the fingerprint against the target URL. Returns a Finding
	// with Confirmed=false if the target is not an instance of this platform.
	Probe(ctx context.Context, client *http.Client, target, hostname string) Finding
}
