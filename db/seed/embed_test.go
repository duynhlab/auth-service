package seed

import (
	"io/fs"
	"strings"
	"testing"
)

// TestFSEmbedsSeed verifies the demo seed SQL is embedded and applied by the
// `seed` subcommand (via migratex, which reads the "sql" subtree).
func TestFSEmbedsSeed(t *testing.T) {
	entries, err := fs.ReadDir(FS, "sql")
	if err != nil {
		t.Fatalf("ReadDir(sql): %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("no seed files embedded under sql/")
	}
}

// TestNoPlaintextSessionTokens guards the security fix: demo seed must contain
// only bcrypt users, never plaintext session tokens.
func TestNoPlaintextSessionTokens(t *testing.T) {
	b, err := fs.ReadFile(FS, "sql/000001_demo_users.up.sql")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if strings.Contains(strings.ToLower(string(b)), "insert into sessions") {
		t.Error("demo seed must not INSERT plaintext session tokens")
	}
}
