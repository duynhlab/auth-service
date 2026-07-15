package v1

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// Business metrics for auth, answering the on-call questions that matter for
// the identity surface:
//  1. Are registrations succeeding, or bouncing on conflicts/infra?  → registrations{result}
//  2. Is refresh-token rotation healthy, and is anyone replaying a
//     stolen token?                                                   → refresh.operations{result}
//
// Instruments ride the global OTel MeterProvider that obsx.SetupObservability
// installs (RFC-0014 OTLP pipeline → collector → VictoriaMetrics). Before that
// setup the global provider is a no-op, so package-init here is safe. Names are
// OTel-style; the collector renders them as auth_registrations_total and
// auth_refresh_operations_total.
//
// Labels are bounded to enumerable outcomes (RFC-0017 D-9): no ids, and never
// any PII (no username/email) — those identify a person and would explode
// cardinality besides.
var (
	meter = otel.Meter("auth-service")

	registrationsCounter, _ = meter.Int64Counter("auth.registrations.total",
		metric.WithDescription("User registration attempts by outcome"))
	refreshOpsCounter, _ = meter.Int64Counter("auth.refresh.operations.total",
		metric.WithDescription("Refresh-token rotation attempts by outcome"))
)

// Registration outcomes (bounded). conflict = username/email already taken;
// error = an infrastructure failure (hashing, persistence, token minting).
const (
	regSuccess  = "success"
	regConflict = "conflict"
	regError    = "error"
)

// Refresh-rotation outcomes (bounded). reuse_detected is the stolen-token
// replay branch — a critical security signal — and is counted whether or not
// the family revoke that follows it succeeds. Infrastructure failures (DB,
// signer) are deliberately not counted here; they surface via the otelpgx DB
// span and pool error signals.
const (
	refreshRotated = "rotated"
	refreshInvalid = "invalid"
	refreshExpired = "expired"
	refreshReuse   = "reuse_detected"
)

// recordRegistration counts one registration attempt with its outcome. Called
// exactly once per Register call, on every terminal path.
func recordRegistration(ctx context.Context, result string) {
	registrationsCounter.Add(ctx, 1, metric.WithAttributes(attribute.String("result", result)))
}

// recordRefresh counts one refresh-token rotation outcome. Called exactly once
// per Refresh call on each business outcome (rotated/invalid/expired/reuse);
// infrastructure failures return before recording.
func recordRefresh(ctx context.Context, result string) {
	refreshOpsCounter.Add(ctx, 1, metric.WithAttributes(attribute.String("result", result)))
}
