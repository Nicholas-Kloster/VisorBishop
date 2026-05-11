package fingerprint

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/Nicholas-Kloster/VisorBishop/internal/probe"
)

// LangSmithProber detects LangChain LangSmith self-hosted instances and
// extracts customer_info from the unauthenticated /api/v1/info endpoint.
//
// Reference: case-studies/commercial/langsmith-deep-dive-survey-2026-05-10.md
type LangSmithProber struct{}

func (p LangSmithProber) ID() Platform { return LangSmith }

// langsmithInfoResponse maps the fields LangSmith /api/v1/info returns.
// All fields are optional — older versions (v0.10.x) omit customer_info.
type langsmithInfoResponse struct {
	Version              string `json:"version"`
	GitSHA               string `json:"git_sha"`
	LicenseExpirationTime string `json:"license_expiration_time"`
	CustomerInfo *struct {
		CustomerID   string `json:"customer_id"`
		CustomerName string `json:"customer_name"`
	} `json:"customer_info"`
	InstanceFlags map[string]interface{} `json:"instance_flags"`
}

func (p LangSmithProber) Probe(ctx context.Context, client *http.Client, target, hostname string) Finding {
	f := Finding{
		Target:   target,
		Hostname: hostname,
		Platform: LangSmith,
		Auth:     AuthUnknown,
		Severity: SevNone,
	}

	// Probe /api/v1/info — unauthenticated by design on LangSmith
	r := probe.Get(ctx, client, target+"/api/v1/info", hostname, 8192)
	f.LatencyMS = r.LatencyMS
	if r.Err != nil || r.Status != 200 || len(r.Body) == 0 {
		return f
	}

	var info langsmithInfoResponse
	if err := json.Unmarshal(r.Body, &info); err != nil {
		return f
	}
	// LangSmith info responses always have `version`. But ZenML, MLflow, and
	// other Python-FastAPI services also expose `/api/v1/info` with a
	// `version` field. To disambiguate, we require at least ONE
	// LangSmith-specific marker: license_expiration_time, customer_info, or
	// instance_flags with a known LangSmith flag.
	if info.Version == "" {
		return f
	}
	hasLangSmithMarker := info.LicenseExpirationTime != "" ||
		info.CustomerInfo != nil ||
		(info.InstanceFlags != nil && (info.InstanceFlags["playground_auth_bypass_enabled"] != nil ||
			info.InstanceFlags["self_hosted_jit_provisioning_enabled"] != nil ||
			info.InstanceFlags["dataset_examples_multipart_enabled"] != nil))
	if !hasLangSmithMarker {
		return f
	}

	f.Confirmed = true
	f.Version = info.Version
	f.GitSHA = info.GitSHA
	f.LicenseExpiry = info.LicenseExpirationTime

	indicators := make(map[string]interface{})
	if info.CustomerInfo != nil {
		indicators["customer_name"] = info.CustomerInfo.CustomerName
		indicators["customer_id"] = info.CustomerInfo.CustomerID
		f.Notes = append(f.Notes, "customer_info disclosed via unauthenticated /api/v1/info")
	}
	// Surface specific high-signal instance_flags
	if info.InstanceFlags != nil {
		for _, flag := range []string{
			"playground_auth_bypass_enabled",
			"self_hosted_jit_provisioning_enabled",
			"phone_home_enabled",
		} {
			if v, ok := info.InstanceFlags[flag]; ok {
				indicators[flag] = v
			}
		}
	}
	f.Indicators = indicators

	// Verify auth posture on the protected /api/v1/sessions endpoint
	r2 := probe.Get(ctx, client, target+"/api/v1/sessions", hostname, 256)
	switch {
	case r2.Status == 200:
		// Should never happen on LangSmith — protected endpoint, would be a CRITICAL find
		f.Auth = AuthOpen
		f.Severity = SevCritical
		f.Notes = append(f.Notes, "UNEXPECTED: /api/v1/sessions returned 200 unauth (possible misconfiguration)")
	case r2.Status == 401 || r2.Status == 403:
		f.Auth = AuthInfoOnly
		// Severity based on whether customer_info leaked
		if info.CustomerInfo != nil && info.CustomerInfo.CustomerName != "" {
			f.Severity = SevHigh
		} else {
			f.Severity = SevMedium
		}
	default:
		f.Auth = AuthUnknown
	}

	return f
}
