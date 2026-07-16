package v1

import (
	"context"
	"time"

	"github.com/duynhlab/pkg/obsx"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// Business metrics for auth, answering the on-call questions that matter for
// the identity surface:
//  1. Are registrations succeeding, or bouncing on conflicts/infra?  → registrations{result}
//  2. Is refresh-token rotation healthy, and is anyone replaying a
//     stolen token?                                                   → refresh.operations{result}
//  3. How often are token families torn down, and is it routine
//     logout or theft response?                                       → family_revocations{reason}
//  4. How much request latency is bcrypt itself, not SQL?             → password_hash.duration{op}
//
// Instruments ride the global OTel MeterProvider that obsx.SetupObservability
// installs (RFC-0014 OTLP pipeline → collector → VictoriaMetrics). Before that
// setup the global provider is a no-op, so package-init here is safe. Names are
// OTel-style; the collector renders them as auth_registrations_total,
// auth_refresh_operations_total, auth_family_revocations_total, and
// auth_password_hash_duration_seconds.
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
	familyRevocationsCounter, _ = meter.Int64Counter("auth.family_revocations.total",
		metric.WithDescription("Refresh-token family revocations by reason"))
	passwordHashDuration, _ = meter.Float64Histogram("auth.password_hash.duration",
		metric.WithDescription("bcrypt hash/compare operation duration"),
		metric.WithUnit("s"),
		// Second-scale SLO buckets — obsx installs Views only for the named HTTP
		// instruments, so without this hint the SDK's millisecond-scale default
		// boundaries (0,5,…,10000) collapse every sub-5s bcrypt op into bucket 0.
		metric.WithExplicitBucketBoundaries(obsx.DurationBuckets...))
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

// Family-revocation reasons (bounded). logout = a user-initiated logout;
// reuse = a stolen-token replay (reuse detection) forced the family down. Only
// a revoke that actually succeeded is counted — a failed revoke leaves the
// family live and returns 500, so it is not a revocation event.
const (
	revokeLogout = "logout"
	revokeReuse  = "reuse"
)

// bcrypt operation labels (bounded). hash = GenerateFromPassword on register;
// compare = CompareHashAndPassword on login.
const (
	hashOp    = "hash"
	compareOp = "compare"
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

// recordFamilyRevocation counts one successful refresh-token-family revocation
// with its reason. Called exactly once per revocation, immediately after the
// underlying RevokeFamily succeeds (logout path and reuse-detection path).
//
// This measures revoke operations, not distinct families: RevokeFamily is
// idempotent, so a replay storm re-tearing-down an already-dead family
// increments this per attempt. Read a spike as "revoke activity", not "N newly
// compromised families" — reuse detections are counted separately via
// refresh.operations{result=reuse_detected}.
func recordFamilyRevocation(ctx context.Context, reason string) {
	familyRevocationsCounter.Add(ctx, 1, metric.WithAttributes(attribute.String("reason", reason)))
}

// startHashTimer begins timing a bcrypt operation and returns a stop func that
// records the elapsed seconds under op. Call the returned func immediately
// after the bcrypt call (not deferred to function end) so the sample isolates
// bcrypt cost from the surrounding SQL/token work.
func startHashTimer(ctx context.Context, op string) func() {
	start := time.Now()
	return func() {
		passwordHashDuration.Record(ctx, time.Since(start).Seconds(),
			metric.WithAttributes(attribute.String("op", op)))
	}
}
