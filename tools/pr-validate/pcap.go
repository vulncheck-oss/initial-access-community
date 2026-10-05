package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

// RulePcapLinkType identifies capture-link-layer findings.
const RulePcapLinkType = "pcap-linktype"

// pcapngMagic is the big-endian magic of a pcapng Section Header Block; a
// classic pcap file starts with a different (byte-order-dependent) magic.
const pcapngMagic = 0x0a0d0d0a

// lintPcap reads every *.pcap/*.pcapng file under the entry directory and
// checks its capture link type. Ethernet is the expected type and is not
// reported; Linux "cooked" captures (SLL v1/v2) are errors because they are not
// portable or replayable like an Ethernet capture; any other link type is a
// warning. A file that cannot be parsed as a capture is an error.
func lintPcap(dir, entryID string) int {
	failed := 0
	root := filepath.Join(dir, entryID)
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil // skip unreadable paths and directories
		}
		switch strings.ToLower(filepath.Ext(path)) {
		case ".pcap", ".pcapng":
		default:
			return nil
		}

		lt, err := pcapLinkType(path)
		if err != nil {
			log.Printf("ERROR: %s - unable to read capture %s: %v [%s]", strings.ToUpper(entryID), path, err, RulePcapLinkType)
			failed++
			return nil
		}
		switch lt {
		case layers.LinkTypeEthernet:
			// Expected; not reported.
		case layers.LinkTypeLinuxSLL, layers.LinkTypeLinuxSLL2:
			log.Printf("ERROR: %s - %s is a Linux cooked capture (%s); recapture on an Ethernet interface [%s]",
				strings.ToUpper(entryID), path, lt, RulePcapLinkType)
			failed++
		default:
			log.Printf("WARN: %s - %s has unexpected link type %s (expected Ethernet) [%s]",
				strings.ToUpper(entryID), path, lt, RulePcapLinkType)
		}
		return nil
	})
	return failed
}

// pcapLinkType returns the capture link type of a pcap or pcapng file, reading
// only the header with the pure-Go pcapgo reader (no libpcap). For pcapng it is
// the link type of the first interface.
func pcapLinkType(path string) (layers.LinkType, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	br := bufio.NewReader(f)
	magic, err := br.Peek(4)
	if err != nil {
		return 0, fmt.Errorf("reading magic: %w", err)
	}

	if binary.BigEndian.Uint32(magic) == pcapngMagic {
		r, err := pcapgo.NewNgReader(br, pcapgo.DefaultNgReaderOptions)
		if err != nil {
			return 0, err
		}
		return r.LinkType(), nil
	}
	r, err := pcapgo.NewReader(br)
	if err != nil {
		return 0, err
	}
	return r.LinkType(), nil
}
