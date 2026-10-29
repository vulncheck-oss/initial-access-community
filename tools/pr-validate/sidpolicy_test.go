package main

import (
	"os"
	"testing"
)

// TestMain sets the SID block bounds the lint tests assume. Production code
// loads these from .sid.json (see loadSIDPolicy); the tests set them directly
// so they need no policy file on disk. These mirror this repo's .sid.json
// block, and the fixtures carry SIDs inside it.
func TestMain(m *testing.M) {
	sidMin = 12_900_001
	sidMax = 13_000_001
	os.Exit(m.Run())
}
