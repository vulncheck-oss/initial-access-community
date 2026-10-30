package main

import (
	"os"
	"testing"
)

// TestMain pins a fixed SID block for the lint tests instead of loading one
// from .sid.json, so the bounds and the fixtures below are identical in the
// private and community repos and the export rewrites nothing. The block is the
// private feed's real range [12700001, 12800001] -- a real allocated band (not a
// made-up one that might collide with a third party's), and not sensitive, so it
// is fine to carry in the community mirror too. This is test data only; each
// repo's live feed is numbered from its own .sid.json block (see loadSIDPolicy).
// The fixtures carry SIDs inside [12700001, 12800001].
func TestMain(m *testing.M) {
	sidMin = 12_700_001
	sidMax = 12_800_001
	os.Exit(m.Run())
}
