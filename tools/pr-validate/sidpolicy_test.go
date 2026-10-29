package main

import (
	"os"
	"testing"
)

// TestMain sets a synthetic SID block for the lint tests, independent of this
// repo's real .sid.json block. Production code loads the real bounds from
// .sid.json (see loadSIDPolicy); the tests set their own so the fixtures are
// identical in the private and community repos and the export never rewrites
// them. The fixtures carry SIDs inside [90000001, 90000101].
func TestMain(m *testing.M) {
	sidMin = 90_000_001
	sidMax = 90_000_101
	os.Exit(m.Run())
}
