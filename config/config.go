// Package config provides centralized configuration management for all microservices
// with validation, type safety, and clear documentation for SRE/DevOps teams.
//
// Configuration Sources (12-factor app principles):
//  1. Default values (hardcoded)
//  2. .env file (local development via godotenv)
//  3. Environment variables (Kubernetes runtime)
//  4. Helm values → deployment.yaml → env/extraEnv → container environment
//
// Usage:
//
//	import "github.com/duynhlab/auth-service/config"
//
//	func main() {
//	    cfg := config.Load()
//	    if err := cfg.Validate(); err != nil {
//	        log.Fatal(err)
//	    }
//	    // Use cfg.Service.Port, cfg.Tracing.Endpoint, etc.
//	}
package config

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

// defaultServiceName is the fallback service name when SERVICE_NAME is not set
const defaultServiceName = "unknown"

// Config holds all configuration for a microservice
type Config struct {
	Service         ServiceConfig   // Service-specific settings (port, name, version)
	Tracing         TracingConfig   // OpenTelemetry/Tempo configuration
	Profiling       ProfilingConfig // Pyroscope continuous profiling
	Logging         LoggingConfig   // Structured logging (Zap)
	Metrics         MetricsConfig   // Prometheus metrics
	Database        DatabaseConfig  // PostgreSQL database configuration
	JWT             JWTConfig       // RS256 access-token signing (the only credential)
	ShutdownTimeout int             // Graceful shutdown timeout in seconds - from SHUTDOWN_TIMEOUT env (default: 10)
	// ReadinessDrainDelay: delay after failing readiness before shutting down the HTTP server.
	// This gives Kubernetes/Service routing time to stop sending new traffic.
	// From READINESS_DRAIN_DELAY env (default: 5s, max: 30s).
	ReadinessDrainDelay int
}

// JWTConfig defines RS256 access-token signing — the only credential (RFC-0009
// Phase 5). If PrivateKeyPEM is empty, an ephemeral key is generated at
// startup for local/dev convenience; production refuses to start without a
// stable key (see main.go).
type JWTConfig struct {
	Issuer     string        // Token issuer (iss) - from JWT_ISSUER env
	Audience   string        // Token audience (aud) - from JWT_AUDIENCE env
	AccessTTL  time.Duration // Access-token lifetime - from JWT_ACCESS_TTL env
	RefreshTTL time.Duration // Refresh-token lifetime - from JWT_REFRESH_TTL env (default: 720h / 30d)
	// nolint:gosec // G117: PEM key material is read from env, never logged
	PrivateKeyPEM string // RS256 private key (PEM) - from JWT_PRIVATE_KEY_PEM env (empty = ephemeral)
}

// ServiceConfig defines basic service configuration
type ServiceConfig struct {
	Name    string // Service name (e.g., "auth", "user") - from SERVICE_NAME env
	Port    string // HTTP server port (default: "8080") - from PORT env
	Version string // Service version (optional) - from VERSION env
	Env     string // Environment (dev/staging/production) - from ENV env
}

// TracingConfig defines OpenTelemetry tracing configuration
// Traces are sent to OpenTelemetry Collector for distributed tracing analysis
type TracingConfig struct {
	Enabled     bool    // Enable tracing (default: true) - from TRACING_ENABLED env
	Endpoint    string  // OTel Collector endpoint - from OTEL_COLLECTOR_ENDPOINT env
	SampleRate  float64 // Trace sampling rate (0.0-1.0) - from OTEL_SAMPLE_RATE env
	ServiceName string  // Service name for traces (defaults to ServiceConfig.Name)
}

// ProfilingConfig defines Pyroscope continuous profiling configuration
type ProfilingConfig struct {
	Enabled     bool   // Enable profiling (default: true) - from PROFILING_ENABLED env
	Endpoint    string // Pyroscope endpoint - from PYROSCOPE_ENDPOINT env
	ServiceName string // Service name for profiling (defaults to ServiceConfig.Name)
}

// LoggingConfig defines structured logging configuration
type LoggingConfig struct {
	Level  string // Log level: debug, info, warn, error (default: "info") - from LOG_LEVEL env
	Format string // Log format: json, console (default: "json") - from LOG_FORMAT env
}

// MetricsConfig defines Prometheus metrics configuration
type MetricsConfig struct {
	Enabled bool   // Enable metrics (default: true) - from METRICS_ENABLED env
	Path    string // Metrics endpoint path (default: "/metrics") - from METRICS_PATH env
}

// DatabaseConfig defines PostgreSQL database configuration
// All database connections use separate environment variables (not DATABASE_URL string)
type DatabaseConfig struct {
	Host string // Database host - from DB_HOST env
	Port string // Database port - from DB_PORT env (default: "5432")
	Name string // Database name - from DB_NAME env
	User string // Database user - from DB_USER env
	// nolint:gosec // G117: This is a configuration field for the database password
	Password       string // Database password - from DB_PASSWORD env
	SSLMode        string // SSL mode - from DB_SSLMODE env (default: "disable")
	MaxConnections int    // Max connections - from DB_POOL_MAX_CONNECTIONS env (default: 25)
	PoolMode       string // Pool mode - from DB_POOL_MODE env (optional)
	PoolerType     string // Pooler type - from DB_POOLER_TYPE env (optional)
}

// BuildDSN constructs PostgreSQL connection string from config
func (c *DatabaseConfig) BuildDSN() string {
	// Format: postgresql://user:password@host:port/dbname?sslmode=disable
	hostPort := net.JoinHostPort(c.Host, c.Port)
	return fmt.Sprintf("postgresql://%s:%s@%s/%s?sslmode=%s",
		c.User, c.Password, hostPort, c.Name, c.SSLMode)
}

// Load reads configuration from environment variables with defaults
// It automatically loads .env file if present (for local development)
//
// Priority: .env file < environment variables
// This means ENV vars override .env file values (production takes precedence)
func Load() *Config {
	// Load .env file if exists (for local development)
	// godotenv.Load() fails silently if .env doesn't exist - perfect for production
	_ = godotenv.Load()

	return &Config{
		Service: ServiceConfig{
			Name:    getEnv("SERVICE_NAME", defaultServiceName),
			Port:    getEnv("PORT", "8080"),
			Version: getEnv("VERSION", "dev"),
			Env:     getEnv("ENV", "development"),
		},
		Tracing: TracingConfig{
			Enabled:     getEnvBool("TRACING_ENABLED", true),
			Endpoint:    getEnv("OTEL_COLLECTOR_ENDPOINT", "otel-collector-opentelemetry-collector.monitoring.svc.cluster.local:4318"),
			SampleRate:  getEnvFloat("OTEL_SAMPLE_RATE", 0.1), // 10% default (production)
			ServiceName: getEnv("SERVICE_NAME", defaultServiceName),
		},
		Profiling: ProfilingConfig{
			Enabled:     getEnvBool("PROFILING_ENABLED", true),
			Endpoint:    getEnv("PYROSCOPE_ENDPOINT", "http://pyroscope.monitoring.svc.cluster.local:4040"),
			ServiceName: getEnv("SERVICE_NAME", defaultServiceName),
		},
		Logging: LoggingConfig{
			Level:  getEnv("LOG_LEVEL", "info"),
			Format: getEnv("LOG_FORMAT", "json"),
		},
		Metrics: MetricsConfig{
			Enabled: getEnvBool("METRICS_ENABLED", true),
			Path:    getEnv("METRICS_PATH", "/metrics"),
		},
		JWT: JWTConfig{
			Issuer:        getEnv("JWT_ISSUER", "https://gateway.duynh.me"),
			Audience:      getEnv("JWT_AUDIENCE", "duynhlab-platform"),
			AccessTTL:     getEnvDuration("JWT_ACCESS_TTL", time.Hour),
			RefreshTTL:    getEnvDuration("JWT_REFRESH_TTL", 720*time.Hour),
			PrivateKeyPEM: getEnv("JWT_PRIVATE_KEY_PEM", ""),
		},
		Database: DatabaseConfig{
			Host:           getEnv("DB_HOST", ""),
			Port:           getEnv("DB_PORT", "5432"),
			Name:           getEnv("DB_NAME", ""),
			User:           getEnv("DB_USER", ""),
			Password:       getEnv("DB_PASSWORD", ""),
			SSLMode:        getEnv("DB_SSLMODE", "disable"),
			MaxConnections: getEnvInt("DB_POOL_MAX_CONNECTIONS", 25),
			PoolMode:       getEnv("DB_POOL_MODE", ""),
			PoolerType:     getEnv("DB_POOLER_TYPE", ""),
		},
		ShutdownTimeout:     getEnvDurationSeconds("SHUTDOWN_TIMEOUT", 10),
		ReadinessDrainDelay: getEnvDurationSecondsWithMax("READINESS_DRAIN_DELAY", 5, 30),
	}
}

// Validate performs comprehensive validation of all configuration fields
// Returns detailed error messages for SRE/DevOps troubleshooting
func (c *Config) Validate() error {
	var errs []string

	errs = append(errs, c.validateService()...)
	errs = append(errs, c.validateTracing()...)
	errs = append(errs, c.validateProfiling()...)
	errs = append(errs, c.validateLogging()...)
	errs = append(errs, c.validateDatabase()...)
	errs = append(errs, c.validateJWT()...)

	if len(errs) > 0 {
		return fmt.Errorf("configuration validation failed:\n  - %s", strings.Join(errs, "\n  - "))
	}

	return nil
}

// validateService validates service configuration fields
func (c *Config) validateService() []string {
	var errs []string

	if c.Service.Name == "" || c.Service.Name == defaultServiceName {
		errs = append(errs, "SERVICE_NAME is required (e.g., 'auth', 'user', 'product')")
	}
	if c.Service.Port == "" {
		errs = append(errs, "PORT is required (e.g., '8080')")
	}
	if _, err := strconv.Atoi(c.Service.Port); err != nil {
		errs = append(errs, "PORT must be a valid number, got: "+c.Service.Port)
	}
	validEnvs := []string{"development", "dev", "staging", "stage", "production", "prod"}
	if !contains(validEnvs, c.Service.Env) {
		errs = append(errs, fmt.Sprintf("ENV must be one of %v, got: %s", validEnvs, c.Service.Env))
	}

	return errs
}

// validateTracing validates tracing configuration fields
func (c *Config) validateTracing() []string {
	if !c.Tracing.Enabled {
		return nil
	}

	var errs []string

	if c.Tracing.Endpoint == "" {
		errs = append(errs, "OTEL_COLLECTOR_ENDPOINT is required when tracing is enabled")
	}
	if c.Tracing.SampleRate < 0 || c.Tracing.SampleRate > 1.0 {
		errs = append(errs, fmt.Sprintf("OTEL_SAMPLE_RATE must be between 0.0 and 1.0, got: %.2f", c.Tracing.SampleRate))
	}
	if c.Tracing.ServiceName == "" || c.Tracing.ServiceName == defaultServiceName {
		errs = append(errs, "SERVICE_NAME is required for tracing (used in Tempo queries)")
	}

	return errs
}

// validateProfiling validates profiling configuration fields
func (c *Config) validateProfiling() []string {
	if !c.Profiling.Enabled {
		return nil
	}

	var errs []string

	if c.Profiling.Endpoint == "" {
		errs = append(errs, "PYROSCOPE_ENDPOINT is required when profiling is enabled")
	}
	if c.Profiling.ServiceName == "" || c.Profiling.ServiceName == defaultServiceName {
		errs = append(errs, "SERVICE_NAME is required for profiling (used in Pyroscope UI)")
	}

	return errs
}

// validateLogging validates logging configuration fields
func (c *Config) validateLogging() []string {
	var errs []string

	validLogLevels := []string{"debug", "info", "warn", "error"}
	if !contains(validLogLevels, strings.ToLower(c.Logging.Level)) {
		errs = append(errs, fmt.Sprintf("LOG_LEVEL must be one of %v, got: %s", validLogLevels, c.Logging.Level))
	}
	validLogFormats := []string{"json", "console"}
	if !contains(validLogFormats, strings.ToLower(c.Logging.Format)) {
		errs = append(errs, fmt.Sprintf("LOG_FORMAT must be one of %v, got: %s", validLogFormats, c.Logging.Format))
	}

	return errs
}

// validateDatabase validates database configuration fields
func (c *Config) validateDatabase() []string {
	if c.Database.Host == "" {
		return nil
	}

	var errs []string

	if c.Database.Name == "" {
		errs = append(errs, "DB_NAME is required when DB_HOST is set")
	}
	if c.Database.User == "" {
		errs = append(errs, "DB_USER is required when DB_HOST is set")
	}
	if c.Database.Password == "" {
		errs = append(errs, "DB_PASSWORD is required when DB_HOST is set")
	}
	if c.Database.Port != "" {
		if _, err := strconv.Atoi(c.Database.Port); err != nil {
			errs = append(errs, "DB_PORT must be a valid number, got: "+c.Database.Port)
		}
	}

	return errs
}

// validateJWT validates JWT access-token signing configuration fields
func (c *Config) validateJWT() []string {
	var errs []string

	if c.JWT.Issuer == "" {
		errs = append(errs, "JWT_ISSUER is required (token issuer 'iss' claim)")
	}
	if c.JWT.Audience == "" {
		errs = append(errs, "JWT_AUDIENCE is required (token audience 'aud' claim)")
	}
	if c.JWT.AccessTTL <= 0 {
		errs = append(errs, fmt.Sprintf("JWT_ACCESS_TTL must be greater than 0, got: %s", c.JWT.AccessTTL))
	}
	if c.JWT.RefreshTTL <= c.JWT.AccessTTL {
		errs = append(errs, fmt.Sprintf("JWT_REFRESH_TTL (%s) must be greater than JWT_ACCESS_TTL (%s)", c.JWT.RefreshTTL, c.JWT.AccessTTL))
	}

	return errs
}

// IsDevelopment returns true if running in development environment
func (c *Config) IsDevelopment() bool {
	env := strings.ToLower(c.Service.Env)
	return env == "development" || env == "dev"
}

// IsProduction returns true if running in production environment
func (c *Config) IsProduction() bool {
	env := strings.ToLower(c.Service.Env)
	return env == "production" || env == "prod"
}

// Helper functions for environment variable parsing

// getEnv reads an environment variable with a default fallback
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// getEnvBool reads a boolean environment variable with a default fallback
// Accepts: "true", "1", "yes" for true | "false", "0", "no" for false
func getEnvBool(key string, defaultValue bool) bool {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	value = strings.ToLower(value)
	return value == "true" || value == "1" || value == "yes"
}

// getEnvInt reads an integer environment variable with a default fallback
// Returns default if parsing fails
func getEnvInt(key string, defaultValue int) int {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	intValue, err := strconv.Atoi(value)
	if err != nil {
		return defaultValue
	}
	return intValue
}

// getEnvFloat reads a float64 environment variable with a default fallback
// Returns default if parsing fails
func getEnvFloat(key string, defaultValue float64) float64 {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	floatValue, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return defaultValue
	}
	return floatValue
}

// getEnvDuration reads a Go-duration env var (e.g. "1h", "30m") and returns it
// as a time.Duration. Returns the default on missing or invalid values.
func getEnvDuration(key string, defaultValue time.Duration) time.Duration {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	d, err := time.ParseDuration(value)
	if err != nil {
		return defaultValue
	}
	return d
}

// getEnvDurationSeconds reads a duration environment variable and returns seconds as int
// Accepts Go duration format (e.g., "10s", "30s", "1m")
// Default: 10 seconds
// Max: 60 seconds (safety limit)
// Returns default on invalid values (silent fallback for startup safety)
func getEnvDurationSeconds(key string, defaultValueSeconds int) int {
	const maxSeconds = 60

	timeoutStr := os.Getenv(key)
	if timeoutStr == "" {
		return defaultValueSeconds
	}

	timeout, err := time.ParseDuration(timeoutStr)
	if err != nil {
		// Invalid format - use default (silent fallback for startup safety)
		return defaultValueSeconds
	}

	// Convert to seconds
	seconds := int(timeout.Seconds())

	// Validate: must be positive and within reasonable limit
	if seconds <= 0 || seconds > maxSeconds {
		// Invalid value - use default (silent fallback for startup safety)
		return defaultValueSeconds
	}

	return seconds
}

// GetShutdownTimeoutDuration returns shutdown timeout as time.Duration
// Convenience method for use in main.go
func (c *Config) GetShutdownTimeoutDuration() time.Duration {
	return time.Duration(c.ShutdownTimeout) * time.Second
}

// getEnvDurationSecondsWithMax reads a duration env var and returns seconds as int.
// Accepts Go duration format (e.g., "5s", "30s", "1m").
// Returns default on invalid values (silent fallback for startup safety).
func getEnvDurationSecondsWithMax(key string, defaultValueSeconds int, maxSeconds int) int {
	timeoutStr := os.Getenv(key)
	if timeoutStr == "" {
		return defaultValueSeconds
	}

	timeout, err := time.ParseDuration(timeoutStr)
	if err != nil {
		return defaultValueSeconds
	}

	seconds := int(timeout.Seconds())
	if seconds <= 0 || seconds > maxSeconds {
		return defaultValueSeconds
	}

	return seconds
}

// GetReadinessDrainDelayDuration returns readiness drain delay as time.Duration.
func (c *Config) GetReadinessDrainDelayDuration() time.Duration {
	return time.Duration(c.ReadinessDrainDelay) * time.Second
}

// contains checks if a string slice contains a specific value
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if strings.EqualFold(s, item) {
			return true
		}
	}
	return false
}
