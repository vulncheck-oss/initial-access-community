package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

type serializableNetworkLayer interface {
	gopacket.NetworkLayer
	gopacket.SerializableLayer
}

func writePcapPacket(t *testing.T, path string, networkLayer serializableNetworkLayer) {
	t.Helper()

	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}

	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 1},
		DstMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 2},
		EthernetType: layers.EthernetTypeIPv4,
	}
	if _, ok := networkLayer.(*layers.IPv6); ok {
		eth.EthernetType = layers.EthernetTypeIPv6
	}

	udp := &layers.UDP{SrcPort: 12345, DstPort: 53}
	if err := udp.SetNetworkLayerForChecksum(networkLayer); err != nil {
		t.Fatal(err)
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, networkLayer, udp, gopacket.Payload("test")); err != nil {
		t.Fatal(err)
	}
	data := buf.Bytes()
	if err := w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Unix(1_700_000_000, 0), CaptureLength: len(data), Length: len(data)}, data); err != nil {
		t.Fatal(err)
	}
}

func Test_pcapHasLoopback(t *testing.T) {
	tests := []struct {
		name    string
		network serializableNetworkLayer
		want    bool
	}{
		{
			name:    "synthetic IPv4 endpoints",
			network: &layers.IPv4{Version: 4, TTL: 64, SrcIP: net.IPv4(10, 12, 70, 1), DstIP: net.IPv4(10, 9, 49, 1), Protocol: layers.IPProtocolUDP},
		},
		{
			name:    "IPv4 loopback source",
			network: &layers.IPv4{Version: 4, TTL: 64, SrcIP: net.IPv4(127, 0, 0, 1), DstIP: net.IPv4(127, 0, 0, 2), Protocol: layers.IPProtocolUDP},
			want:    true,
		},
		{
			name:    "IPv4 loopback destination",
			network: &layers.IPv4{Version: 4, TTL: 64, SrcIP: net.IPv4(10, 12, 70, 1), DstIP: net.IPv4(127, 1, 2, 3), Protocol: layers.IPProtocolUDP},
			want:    true,
		},
		{
			name:    "synthetic IPv6 endpoints",
			network: &layers.IPv6{Version: 6, HopLimit: 64, SrcIP: net.ParseIP("fd00::1"), DstIP: net.ParseIP("fd00::2"), NextHeader: layers.IPProtocolUDP},
		},
		{
			name:    "IPv6 loopback source",
			network: &layers.IPv6{Version: 6, HopLimit: 64, SrcIP: net.IPv6loopback, DstIP: net.ParseIP("fd00::2"), NextHeader: layers.IPProtocolUDP},
			want:    true,
		},
		{
			name:    "IPv6 loopback destination",
			network: &layers.IPv6{Version: 6, HopLimit: 64, SrcIP: net.ParseIP("fd00::1"), DstIP: net.IPv6loopback, NextHeader: layers.IPProtocolUDP},
			want:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "capture.pcap")
			writePcapPacket(t, path, tt.network)

			got, err := pcapHasLoopback(path)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Fatalf("pcapHasLoopback() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_lintPcap_rejectsLoopback(t *testing.T) {
	dir := t.TempDir()
	entryID := "cve-2026-0001"
	entryDir := filepath.Join(dir, entryID)
	if err := os.Mkdir(entryDir, 0o755); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(entryDir, "00-exploited-unencrypted.pcap")
	writePcapPacket(t, path, &layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    net.IPv4(127, 0, 0, 1),
		DstIP:    net.IPv4(127, 0, 0, 1),
		Protocol: layers.IPProtocolUDP,
	})

	if failed := lintPcap(dir, entryID); failed != 1 {
		t.Fatalf("lintPcap() failures = %d, want 1", failed)
	}
}
