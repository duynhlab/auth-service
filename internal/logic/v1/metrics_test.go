package v1

import (
	"context"
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
	regMetric     = "auth.registrations.total"
	refreshMetric = "auth.refresh.operations.total"
)

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
