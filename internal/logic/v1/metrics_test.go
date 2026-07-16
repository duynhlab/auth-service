package v1

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/duynhlab/auth-service/internal/core/domain"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// reader is the process-wide ManualReader wired as the global MeterProvider.
// The OTel global is FIRST-WINS — only one SetMeterProvider takes effect per
// test binary — so TestMain installs it once before any test runs, and the
// package-init instruments in metrics.go delegate to it.
var reader = sdkmetric.NewManualReader()

func TestMain(m *testing.M) {
	otel.SetMeterProvider(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)))
	os.Exit(m.Run())
}

// snapshot returns the current cumulative value of counter `name` for the given
// result label (0 when no data point exists yet). Reading a baseline and
// asserting the delta keeps the tests robust against increments other tests in
// this binary (service_test.go drives Register/Refresh) add to the same
// process-wide cumulative counters.
func snapshot(t *testing.T, name, result string) int64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("collect metrics: %v", err)
	}
	for _, sm := range rm.ScopeMetrics {
		for _, md := range sm.Metrics {
			if md.Name == name {
				return sumForResult(t, md, result)
			}
		}
	}
	return 0
}

// sumForResult returns the value of the counter data point carrying
// result=<result> (0 when absent), failing the test if the metric is not an
// int64 sum.
func sumForResult(t *testing.T, md metricdata.Metrics, result string) int64 {
	t.Helper()
	sum, ok := md.Data.(metricdata.Sum[int64])
	if !ok {
		t.Fatalf("%s: unexpected data type %T", md.Name, md.Data)
	}
	for _, dp := range sum.DataPoints {
		if v, ok := dp.Attributes.Value(attribute.Key("result")); ok && v.AsString() == result {
			return dp.Value
		}
	}
	return 0
}

// assertDelta records nothing itself; it asserts that between `before` and now
// the counter grew by exactly `want`, proving each record call adds exactly one
// under the expected label.
func assertDelta(t *testing.T, name, result string, before, want int64) {
	t.Helper()
	if got := snapshot(t, name, result) - before; got != want {
		t.Errorf("%s{result=%q}: delta = %d, want %d", name, result, got, want)
	}
}

const (
	regMetric        = "auth.registrations.total"
	refreshMetric    = "auth.refresh.operations.total"
	revocationMetric = "auth.family_revocations.total"
	hashDurMetric    = "auth.password_hash.duration"
)

// findMetric returns the collected metric named `name` (and whether it exists).
func findMetric(t *testing.T, name string) (metricdata.Metrics, bool) {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("collect metrics: %v", err)
	}
	for _, sm := range rm.ScopeMetrics {
		for _, md := range sm.Metrics {
			if md.Name == name {
				return md, true
			}
		}
	}
	return metricdata.Metrics{}, false
}

// counterFor returns the cumulative value of int64 counter `name` for the data
// point carrying key=val (0 when absent).
func counterFor(t *testing.T, name, key, val string) int64 {
	t.Helper()
	md, ok := findMetric(t, name)
	if !ok {
		return 0
	}
	sum, ok := md.Data.(metricdata.Sum[int64])
	if !ok {
		t.Fatalf("%s: unexpected data type %T", name, md.Data)
	}
	for _, dp := range sum.DataPoints {
		if v, ok := dp.Attributes.Value(attribute.Key(key)); ok && v.AsString() == val {
			return dp.Value
		}
	}
	return 0
}

// histCountFor returns the sample count of float64 histogram `name` for the
// data point carrying key=val (0 when absent).
func histCountFor(t *testing.T, name, key, val string) uint64 {
	t.Helper()
	md, ok := findMetric(t, name)
	if !ok {
		return 0
	}
	hist, ok := md.Data.(metricdata.Histogram[float64])
	if !ok {
		t.Fatalf("%s: unexpected data type %T", name, md.Data)
	}
	for _, dp := range hist.DataPoints {
		if v, ok := dp.Attributes.Value(attribute.Key(key)); ok && v.AsString() == val {
			return dp.Count
		}
	}
	return 0
}

// TestRecordRegistration asserts the bounded result labels and exactly-once
// accounting: two success + one conflict + one error records grow each series
// by precisely that many.
func TestRecordRegistration(t *testing.T) {
	ctx := context.Background()
	base := map[string]int64{
		regSuccess:  snapshot(t, regMetric, regSuccess),
		regConflict: snapshot(t, regMetric, regConflict),
		regError:    snapshot(t, regMetric, regError),
	}

	recordRegistration(ctx, regSuccess)
	recordRegistration(ctx, regSuccess)
	recordRegistration(ctx, regConflict)
	recordRegistration(ctx, regError)

	assertDelta(t, regMetric, regSuccess, base[regSuccess], 2)
	assertDelta(t, regMetric, regConflict, base[regConflict], 1)
	assertDelta(t, regMetric, regError, base[regError], 1)
}

// TestRecordRefresh asserts the four bounded refresh outcomes each increment
// their own series by exactly one — reuse_detected included, the critical
// stolen-token replay signal.
func TestRecordRefresh(t *testing.T) {
	ctx := context.Background()
	outcomes := []string{refreshRotated, refreshInvalid, refreshExpired, refreshReuse}
	base := make(map[string]int64, len(outcomes))
	for _, o := range outcomes {
		base[o] = snapshot(t, refreshMetric, o)
	}

	for _, o := range outcomes {
		recordRefresh(ctx, o)
	}

	for _, o := range outcomes {
		assertDelta(t, refreshMetric, o, base[o], 1)
	}
}

// TestServiceCallSitesRecordExactlyOnce drives the real logic through fakes to
// prove the counters are wired at the call sites exactly once per operation. A
// missing or duplicated record call (which the recorder-level tests above cannot
// see) shows up here as a wrong delta.
func TestServiceCallSitesRecordExactlyOnce(t *testing.T) {
	ctx := context.Background()

	// Register happy path: fakes default to ExistsByUsernameOrEmail=false and
	// Create=id 0, so this reaches the success return exactly once.
	svc := NewAuthService(&fakeUserRepository{}, &fakeRefreshTokenRepository{}, newTestSigner(t), time.Hour)
	baseReg := snapshot(t, regMetric, regSuccess)
	if _, err := svc.Register(ctx, domain.RegisterRequest{Username: "u", Email: "u@example.test", Password: "pw"}); err != nil {
		t.Fatalf("register: %v", err)
	}
	assertDelta(t, regMetric, regSuccess, baseReg, 1)

	// Refresh rotation happy path: an unused, unexpired token that Rotate claims.
	refRepo := &fakeRefreshTokenRepository{
		getByHash: func(context.Context, string) (*domain.RefreshTokenRow, error) {
			return &domain.RefreshTokenRow{UserID: 1, FamilyID: "fam", ExpiresAt: time.Now().Add(time.Hour)}, nil
		},
	}
	svc2 := NewAuthService(&fakeUserRepository{}, refRepo, newTestSigner(t), time.Hour)
	baseRot := snapshot(t, refreshMetric, refreshRotated)
	if _, err := svc2.Refresh(ctx, "raw-token"); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	assertDelta(t, refreshMetric, refreshRotated, baseRot, 1)
}

// TestRecordFamilyRevocation asserts the two bounded reason labels and
// exactly-once accounting for the family-revocation recorder.
func TestRecordFamilyRevocation(t *testing.T) {
	ctx := context.Background()
	baseLogout := counterFor(t, revocationMetric, "reason", revokeLogout)
	baseReuse := counterFor(t, revocationMetric, "reason", revokeReuse)

	recordFamilyRevocation(ctx, revokeLogout)
	recordFamilyRevocation(ctx, revokeLogout)
	recordFamilyRevocation(ctx, revokeReuse)

	if got := counterFor(t, revocationMetric, "reason", revokeLogout) - baseLogout; got != 2 {
		t.Errorf("%s{reason=logout}: delta = %d, want 2", revocationMetric, got)
	}
	if got := counterFor(t, revocationMetric, "reason", revokeReuse) - baseReuse; got != 1 {
		t.Errorf("%s{reason=reuse}: delta = %d, want 1", revocationMetric, got)
	}
}

// TestStartHashTimer asserts each timer records exactly one sample under its
// bounded op label.
func TestStartHashTimer(t *testing.T) {
	ctx := context.Background()
	baseHash := histCountFor(t, hashDurMetric, "op", hashOp)
	baseCmp := histCountFor(t, hashDurMetric, "op", compareOp)

	startHashTimer(ctx, hashOp)()
	startHashTimer(ctx, compareOp)()
	startHashTimer(ctx, compareOp)()

	if got := histCountFor(t, hashDurMetric, "op", hashOp) - baseHash; got != 1 {
		t.Errorf("%s{op=hash}: count delta = %d, want 1", hashDurMetric, got)
	}
	if got := histCountFor(t, hashDurMetric, "op", compareOp) - baseCmp; got != 2 {
		t.Errorf("%s{op=compare}: count delta = %d, want 2", hashDurMetric, got)
	}
}

// TestW2CallSitesRecordExactlyOnce drives the real logic through fakes to prove
// the W2 instruments are wired at the correct call sites: recorded once when the
// operation happens, and NOT recorded when a family revoke fails (the family is
// still live, so it is not a revocation event).
func TestW2CallSitesRecordExactlyOnce(t *testing.T) {
	ctx := context.Background()
	const password = "password123"

	// Register happy path records exactly one password_hash{op=hash}.
	svc := NewAuthService(&fakeUserRepository{}, &fakeRefreshTokenRepository{}, newTestSigner(t), time.Hour)
	baseHash := histCountFor(t, hashDurMetric, "op", hashOp)
	if _, err := svc.Register(ctx, domain.RegisterRequest{Username: "u", Email: "u@example.test", Password: password}); err != nil {
		t.Fatalf("register: %v", err)
	}
	if got := histCountFor(t, hashDurMetric, "op", hashOp) - baseHash; got != 1 {
		t.Errorf("register op=hash count delta = %d, want 1", got)
	}

	// Login with a valid user records exactly one password_hash{op=compare}.
	users := &fakeUserRepository{
		getByUsername: func(context.Context, string) (*domain.UserRow, error) {
			return &domain.UserRow{ID: 7, Username: "alice", Email: "a@example.test", PasswordHash: hashPassword(t, password)}, nil
		},
	}
	baseCmp := histCountFor(t, hashDurMetric, "op", compareOp)
	if _, err := NewAuthService(users, nil, newTestSigner(t), time.Hour).Login(ctx, domain.LoginRequest{Username: "alice", Password: password}); err != nil {
		t.Fatalf("login: %v", err)
	}
	if got := histCountFor(t, hashDurMetric, "op", compareOp) - baseCmp; got != 1 {
		t.Errorf("valid-user login op=compare count delta = %d, want 1", got)
	}

	// Login for an unknown user still records exactly one compare (dummy path).
	baseCmp2 := histCountFor(t, hashDurMetric, "op", compareOp)
	if _, err := NewAuthService(&fakeUserRepository{}, nil, newTestSigner(t), time.Hour).Login(ctx, domain.LoginRequest{Username: "ghost", Password: password}); err == nil {
		t.Fatal("expected error for unknown user")
	}
	if got := histCountFor(t, hashDurMetric, "op", compareOp) - baseCmp2; got != 1 {
		t.Errorf("unknown-user login op=compare count delta = %d, want 1", got)
	}

	// Logout records exactly one family_revocations{reason=logout}.
	knownToken := func(family string) *fakeRefreshTokenRepository {
		return &fakeRefreshTokenRepository{
			getByHash: func(context.Context, string) (*domain.RefreshTokenRow, error) {
				return &domain.RefreshTokenRow{UserID: 1, FamilyID: family, ExpiresAt: time.Now().Add(time.Hour)}, nil
			},
		}
	}
	baseLogout := counterFor(t, revocationMetric, "reason", revokeLogout)
	if err := NewAuthService(&fakeUserRepository{}, knownToken("fam-logout"), newTestSigner(t), time.Hour).Logout(ctx, "raw"); err != nil {
		t.Fatalf("logout: %v", err)
	}
	if got := counterFor(t, revocationMetric, "reason", revokeLogout) - baseLogout; got != 1 {
		t.Errorf("logout reason=logout delta = %d, want 1", got)
	}

	// Failed logout revoke must NOT record (family still live).
	logoutFail := knownToken("fam-logout-fail")
	logoutFail.revoke = func(context.Context, string) error { return errRepo }
	baseLogoutFail := counterFor(t, revocationMetric, "reason", revokeLogout)
	if err := NewAuthService(&fakeUserRepository{}, logoutFail, newTestSigner(t), time.Hour).Logout(ctx, "raw"); !errors.Is(err, errRepo) {
		t.Fatalf("logout: err = %v, want errRepo", err)
	}
	if got := counterFor(t, revocationMetric, "reason", revokeLogout) - baseLogoutFail; got != 0 {
		t.Errorf("failed-revoke reason=logout delta = %d, want 0", got)
	}

	// Reuse (replayed used token) records exactly one family_revocations{reason=reuse}.
	used := time.Now().Add(-time.Minute)
	reusedToken := func(family string) *fakeRefreshTokenRepository {
		return &fakeRefreshTokenRepository{
			getByHash: func(context.Context, string) (*domain.RefreshTokenRow, error) {
				return &domain.RefreshTokenRow{UserID: 1, FamilyID: family, UsedAt: &used, ExpiresAt: time.Now().Add(time.Hour)}, nil
			},
		}
	}
	baseReuse := counterFor(t, revocationMetric, "reason", revokeReuse)
	if _, err := NewAuthService(&fakeUserRepository{}, reusedToken("fam-reuse"), newTestSigner(t), time.Hour).Refresh(ctx, "replayed"); !errors.Is(err, ErrRefreshReuse) {
		t.Fatalf("refresh: err = %v, want ErrRefreshReuse", err)
	}
	if got := counterFor(t, revocationMetric, "reason", revokeReuse) - baseReuse; got != 1 {
		t.Errorf("reuse reason=reuse delta = %d, want 1", got)
	}

	// Lost rotation race (Rotate claimed=false) also funnels through handleReuse
	// and records exactly one reuse revocation.
	racedToken := &fakeRefreshTokenRepository{
		getByHash: func(context.Context, string) (*domain.RefreshTokenRow, error) {
			return &domain.RefreshTokenRow{UserID: 1, FamilyID: "fam-race", ExpiresAt: time.Now().Add(time.Hour)}, nil
		},
		rotate: func(context.Context, string, string, string, int, time.Time) (bool, error) { return false, nil },
	}
	baseRace := counterFor(t, revocationMetric, "reason", revokeReuse)
	if _, err := NewAuthService(&fakeUserRepository{}, racedToken, newTestSigner(t), time.Hour).Refresh(ctx, "raced"); !errors.Is(err, ErrRefreshReuse) {
		t.Fatalf("refresh: err = %v, want ErrRefreshReuse", err)
	}
	if got := counterFor(t, revocationMetric, "reason", revokeReuse) - baseRace; got != 1 {
		t.Errorf("lost-race reason=reuse delta = %d, want 1", got)
	}

	// Failed reuse revoke must NOT record.
	reuseFail := reusedToken("fam-reuse-fail")
	reuseFail.revoke = func(context.Context, string) error { return errRepo }
	baseReuseFail := counterFor(t, revocationMetric, "reason", revokeReuse)
	if _, err := NewAuthService(&fakeUserRepository{}, reuseFail, newTestSigner(t), time.Hour).Refresh(ctx, "replayed"); !errors.Is(err, errRepo) {
		t.Fatalf("refresh: err = %v, want errRepo", err)
	}
	if got := counterFor(t, revocationMetric, "reason", revokeReuse) - baseReuseFail; got != 0 {
		t.Errorf("failed-revoke reason=reuse delta = %d, want 0", got)
	}
}
