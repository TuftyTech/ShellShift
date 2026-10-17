package tunnel

import "testing"

// If this fails, the binary is being built without -tags with_utls and would silently
// drop every Reality node. See CheckBuild and INV-49.
func TestBuildIncludesUTLS(t *testing.T) {
	if err := CheckBuild(); err != nil {
		t.Fatalf("build check failed: %v", err)
	}
}
