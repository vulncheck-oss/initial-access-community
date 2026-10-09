package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/gopacket/gopacket"
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
	r, closer, err := openPcap(path)
	if err != nil {
		return 0, err
	}
	defer closer.Close()

	return r.LinkType(), nil
}

// pcapReader is the subset of pcapgo.Reader and pcapgo.NgReader used here.
type pcapReader interface {
	ReadPacketData() ([]byte, gopacket.CaptureInfo, error)
	LinkType() layers.LinkType
}

// openPcap opens a pcap or pcapng file with the pure-Go pcapgo reader, picking
// the format from the file magic. The caller closes the returned closer.
func openPcap(path string) (pcapReader, io.Closer, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}

	br := bufio.NewReader(f)
	magic, err := br.Peek(4)
	if err != nil {
		f.Close()
		return nil, nil, fmt.Errorf("reading magic: %w", err)
	}

	if binary.BigEndian.Uint32(magic) == pcapngMagic {
		r, err := pcapgo.NewNgReader(br, pcapgo.DefaultNgReaderOptions)
		if err != nil {
			f.Close()
			return nil, nil, err
		}
		return r, f, nil
	}
	r, err := pcapgo.NewReader(br)
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	return r, f, nil
}

// pcapServerPorts returns the sorted, de-duplicated TCP server ports in a
// capture: the destination port of every connection-opening SYN (SYN set, ACK
// clear). A capture whose last record is cut short returns the ports read so
// far along with an error matching io.ErrUnexpectedEOF.
func pcapServerPorts(path string) ([]uint16, error) {
	r, closer, err := openPcap(path)
	if err != nil {
		return nil, err
	}
	defer closer.Close()

	seen := map[uint16]bool{}
	var readErr error
	for {
		data, _, err := r.ReadPacketData()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			readErr = err
			break
		}
		packet := gopacket.NewPacket(data, r.LinkType(), gopacket.DecodeOptions{Lazy: true, NoCopy: true})
		tcp, ok := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
		if ok && tcp.SYN && !tcp.ACK {
			seen[uint16(tcp.DstPort)] = true
		}
	}

	ports := make([]uint16, 0, len(seen))
	for port := range seen {
		ports = append(ports, port)
	}
	slices.Sort(ports)

	if readErr != nil && !errors.Is(readErr, io.ErrUnexpectedEOF) {
		return nil, readErr
	}

	return ports, readErr
}

// maxEngineSnaplen is the largest snapshot length older libpcap releases
// (e.g. the Debian buster libpcap in the ia-feed-builder image) will open.
// Newer libpcap silently clamps a larger header value instead.
const maxEngineSnaplen = 262144

// clampPcapSnaplen returns a path the engines can open for a classic pcap. When
// the file header declares a snapshot length above maxEngineSnaplen, it writes
// a copy into tmpDir with the header value clamped (packet records are
// untouched) and returns that path; otherwise it returns path unchanged.
// pcapng files are returned unchanged.
func clampPcapSnaplen(path, tmpDir string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	if len(data) < 24 {
		return path, nil
	}

	var order binary.ByteOrder
	switch binary.LittleEndian.Uint32(data) {
	case 0xa1b2c3d4, 0xa1b23c4d: // microsecond, nanosecond
		order = binary.LittleEndian
	default:
		switch binary.BigEndian.Uint32(data) {
		case 0xa1b2c3d4, 0xa1b23c4d:
			order = binary.BigEndian
		default:
			return path, nil // pcapng or unknown; leave it to the engine
		}
	}
	if order.Uint32(data[16:20]) <= maxEngineSnaplen {
		return path, nil
	}

	order.PutUint32(data[16:20], maxEngineSnaplen)
	clamped := filepath.Join(tmpDir, filepath.Base(path))
	if err := os.WriteFile(clamped, data, 0o644); err != nil {
		return "", err
	}

	return clamped, nil
}
