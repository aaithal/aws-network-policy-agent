package ebpf

import (
	"encoding/binary"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	goelf "github.com/aws/aws-ebpf-sdk-go/pkg/elfparser"
	goebpfmaps "github.com/aws/aws-ebpf-sdk-go/pkg/maps"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// These tests load the agent's compiled TC programs into the kernel and run
// them on hand-built packets with BPF_PROG_TEST_RUN, which returns the
// program's verdict and the packet as the program left it. They check that a
// denied SYN becomes a well-formed RST only with the flag on, and that the
// egress program passes that RST without recording a flow.
//
// They need root and the objects from `make build-bpf` (in pkg/ebpf/c, or in
// BPF_OBJECTS_DIR), so they skip under `make test`. CI runs them with
// BPF_KERNEL_TESTS=required, which turns a skip into a failure.

// tcVerdict values (TC_ACT_* in include/uapi/linux/pkt_cls.h), as the
// programs return them.
const (
	tcActOK       = 0
	tcActShot     = 2
	tcActRedirect = 7
)

// testPinPrefix keeps the test's pins apart from an agent's on the same node.
// It has no "_": see ctDenyProbePinPrefix.
const testPinPrefix = "TCPRESETTEST"

// tcpFlag* are the TCP header flag bits (RFC 9293 3.1).
const (
	tcpFlagFin = 0x01
	tcpFlagSyn = 0x02
	tcpFlagRst = 0x04
	tcpFlagAck = 0x10
)

const (
	ethHeaderLen  = 14
	ipv4HeaderLen = 20
	ipv6HeaderLen = 40
	tcpHeaderLen  = 20
	// synOptionsLen is a typical SYN's options (MSS, SACK permitted,
	// timestamps, window scale), which the RST must not carry.
	synOptionsLen = 20
	ipProtoTCP    = 6
	ethTypeIPv4   = 0x0800
	ethTypeIPv6   = 0x86dd
	// packetBufferLen is enough for every packet in these tests.
	packetBufferLen = 256
)

var (
	clientMAC = []byte{0x02, 0, 0, 0, 0, 0x01} // the host veth, as seen by the pod
	podMAC    = []byte{0x02, 0, 0, 0, 0, 0x02}
)

// requireBPFKernelTests returns the directory with the BPF objects, or skips
// the test where it can't run (not root, objects not built). Under
// BPF_KERNEL_TESTS=required a skip fails instead, so CI can't pass without
// running it. It mounts bpffs if needed, since the loader pins every map there.
func requireBPFKernelTests(t *testing.T) string {
	t.Helper()
	skip := t.Skipf
	if bpfKernelTestsRequired() {
		skip = t.Fatalf
	}
	if os.Geteuid() != 0 {
		skip("loading BPF programs needs root")
	}
	dir := os.Getenv("BPF_OBJECTS_DIR")
	if dir == "" {
		dir = "c"
	}
	if _, err := os.Stat(filepath.Join(dir, TC_SHARED_BINARY)); err != nil {
		skip("BPF objects not built (make build-bpf): %v", err)
	}
	var fs unix.Statfs_t
	if err := unix.Statfs("/sys/fs/bpf", &fs); err != nil || fs.Type != unix.BPF_FS_MAGIC {
		require.NoError(t, unix.Mount("bpf", "/sys/fs/bpf", "bpf", 0, ""), "mount bpffs")
	}
	t.Cleanup(removeTestPins)
	return dir
}

func bpfKernelTestsRequired() bool {
	return os.Getenv("BPF_KERNEL_TESTS") == "required"
}

// removeTestPins removes what the test pinned. Left behind, the next run's
// loader would reuse those maps, with their old contents, instead of creating
// fresh ones.
func removeTestPins() {
	for _, dir := range []string{utils.BPF_PROGRAMS_PIN_PATH_DIRECTORY, utils.BPF_MAPS_PIN_PATH_DIRECTORY} {
		pins, _ := filepath.Glob(dir + testPinPrefix + "*_*")
		for _, pin := range pins {
			os.Remove(pin)
		}
	}
}

// loadedFamily holds one address family's programs and the maps the tests
// read or write.
type loadedFamily struct {
	ingressFD, egressFD int
	config, pending     goebpfmaps.BpfMap
	conntrack           goebpfmaps.BpfMap
	ingressPodState     goebpfmaps.BpfMap
}

// loadFamily loads the events and shared binaries, then ingressBinary and the
// family's egress binary, with both pods' policy state set to default deny.
// The events and shared binaries come first because the TC programs reference
// their maps. Default deny on both sides means every test packet is denied
// without writing any policy, and the egress side is the hardest case for the
// RST: a pod whose own egress denies everything must still get it out.
func loadFamily(t *testing.T, dir string, v6 bool, ingressBinary string) loadedFamily {
	t.Helper()
	sdk := goelf.New(goelf.Config{NamespacedMaps: utils.NamespacedBPFMaps})
	eventsBinary, egressBinary := EVENTS_BINARY, TC_EGRESS_BINARY
	if v6 {
		eventsBinary, egressBinary = EVENTS_V6_BINARY, TC_V6_EGRESS_BINARY
	}
	var fds []int
	t.Cleanup(func() {
		for _, fd := range fds {
			unix.Close(fd)
		}
	})

	_, globalMaps, err := sdk.LoadBpfFileWithCustomData(goelf.BpfCustomData{
		FilePath: filepath.Join(dir, eventsBinary), CustomPinPath: testPinPrefix + "EVENTS",
	})
	require.NoError(t, err, "load %s", eventsBinary)
	_, sharedMaps, err := sdk.LoadBpfFileWithCustomData(goelf.BpfCustomData{
		FilePath: filepath.Join(dir, TC_SHARED_BINARY), CustomPinPath: testPinPrefix + "SHARED",
	})
	require.NoError(t, err, "load %s", TC_SHARED_BINARY)
	for _, m := range []map[string]goebpfmaps.BpfMap{globalMaps, sharedMaps} {
		for _, bpfMap := range m {
			fds = append(fds, int(bpfMap.MapFD))
		}
	}

	loaded := loadedFamily{
		config:    sharedMaps[TC_CONFIG_MAP],
		pending:   sharedMaps["aws_tcp_reset_pending"],
		conntrack: globalMaps[AWS_CONNTRACK_MAP],
	}
	for _, prog := range []struct {
		binary, prefix, stateMap string
		fd                       *int
		podState                 *goebpfmaps.BpfMap
	}{
		{ingressBinary, testPinPrefix + "INGRESS", utils.TC_INGRESS_POD_STATE_MAP, &loaded.ingressFD, &loaded.ingressPodState},
		{egressBinary, testPinPrefix + "EGRESS", utils.TC_EGRESS_POD_STATE_MAP, &loaded.egressFD, nil},
	} {
		progs, maps, err := sdk.LoadBpfFile(filepath.Join(dir, prog.binary), prog.prefix)
		require.NoError(t, err, "load %s", prog.binary)
		for _, p := range progs {
			*prog.fd = p.Program.ProgFD
			fds = append(fds, p.Program.ProgFD)
		}
		for _, m := range maps {
			fds = append(fds, int(m.MapFD))
		}
		// No policy applies to the pod, and its namespace denies by
		// default, so every new connection to or from it is denied.
		stateMap := maps[prog.stateMap]
		writePodState(t, stateMap, POD_STATE_MAP_KEY, DEFAULT_DENY)
		writePodState(t, stateMap, CLUSTER_POLICY_POD_STATE_MAP_KEY, DEFAULT_ALLOW)
		if prog.podState != nil {
			*prog.podState = stateMap
		}
	}
	return loaded
}

func writePodState(t *testing.T, stateMap goebpfmaps.BpfMap, key, state int) {
	t.Helper()
	k, value := uint32(key), pod_state{state: uint8(state)}
	require.NoError(t, stateMap.CreateUpdateMapEntry(uintptr(unsafe.Pointer(&k)), uintptr(unsafe.Pointer(&value)), 0))
}

// testRun runs the program on packet once, the way the kernel would at its
// TC hook, and returns its verdict and the packet it left.
func testRun(t *testing.T, progFD int, packet []byte) (uint32, []byte) {
	t.Helper()
	out := make([]byte, packetBufferLen)
	attr := struct {
		progFD      uint32
		retval      uint32
		dataSizeIn  uint32
		dataSizeOut uint32
		dataIn      uint64
		dataOut     uint64
		repeat      uint32
		duration    uint32
	}{
		progFD:      uint32(progFD),
		dataSizeIn:  uint32(len(packet)),
		dataSizeOut: uint32(len(out)),
		dataIn:      uint64(uintptr(unsafe.Pointer(&packet[0]))),
		dataOut:     uint64(uintptr(unsafe.Pointer(&out[0]))),
		repeat:      1,
	}
	_, _, errno := unix.Syscall(unix.SYS_BPF, unix.BPF_PROG_TEST_RUN, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
	require.Zero(t, errno, "BPF_PROG_TEST_RUN")
	return attr.retval, out[:attr.dataSizeOut]
}

// tcpSegment is a TCP header with options, and the addresses its checksum
// covers. The options are there because real SYNs carry them, and the RST must
// not: the tests check that the program drops them.
type tcpSegment struct {
	src, dst netip.AddrPort
	seq, ack uint32
	flags    uint8
	options  []byte
}

func (s tcpSegment) bytes() []byte {
	header := make([]byte, tcpHeaderLen+len(s.options))
	binary.BigEndian.PutUint16(header[0:], s.src.Port())
	binary.BigEndian.PutUint16(header[2:], s.dst.Port())
	binary.BigEndian.PutUint32(header[4:], s.seq)
	binary.BigEndian.PutUint32(header[8:], s.ack)
	header[12] = byte(len(header)/4) << 4
	header[13] = s.flags
	binary.BigEndian.PutUint16(header[14:], 64240) // the window Linux advertises in a SYN
	copy(header[tcpHeaderLen:], s.options)
	binary.BigEndian.PutUint16(header[16:], tcpChecksum(s.src.Addr(), s.dst.Addr(), header))
	return header
}

// packet builds an Ethernet frame from the client to the pod carrying s.
func (s tcpSegment) packet() []byte {
	tcp := s.bytes()
	frame := append(append([]byte{}, podMAC...), clientMAC...)
	if s.src.Addr().Is4() {
		frame = binary.BigEndian.AppendUint16(frame, ethTypeIPv4)
		ip := make([]byte, ipv4HeaderLen)
		ip[0] = 0x45
		binary.BigEndian.PutUint16(ip[2:], uint16(ipv4HeaderLen+len(tcp)))
		ip[8] = 64
		ip[9] = ipProtoTCP
		src, dst := s.src.Addr().As4(), s.dst.Addr().As4()
		copy(ip[12:], src[:])
		copy(ip[16:], dst[:])
		binary.BigEndian.PutUint16(ip[10:], ^onesComplementSum(0, ip))
		return append(append(frame, ip...), tcp...)
	}
	frame = binary.BigEndian.AppendUint16(frame, ethTypeIPv6)
	ip := make([]byte, ipv6HeaderLen)
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:], uint16(len(tcp)))
	ip[6] = ipProtoTCP
	ip[7] = 64
	src, dst := s.src.Addr().As16(), s.dst.Addr().As16()
	copy(ip[8:], src[:])
	copy(ip[24:], dst[:])
	return append(append(frame, ip...), tcp...)
}

// The tests check the program's checksums with this independent
// implementation, so a mistake in the program's checksum code shows up as a
// mismatch.
func onesComplementSum(sum uint32, data []byte) uint16 {
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i:]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum > 0xffff {
		sum = sum&0xffff + sum>>16
	}
	return uint16(sum)
}

// tcpChecksum is the TCP checksum of segment, whose checksum field must be
// zero, with the pseudo header of src and dst.
func tcpChecksum(src, dst netip.Addr, segment []byte) uint16 {
	return ^onesComplementSum(uint32(onesComplementSum(0, pseudoHeader(src, dst, len(segment)))), segment)
}

// assertReset checks that frame is the RST answering syn: from the pod back
// to the client, seq 0, acking syn's seq + 1, no options, valid checksums.
func assertReset(t *testing.T, syn tcpSegment, frame []byte) {
	t.Helper()
	ipLen := ipv4HeaderLen
	if syn.src.Addr().Is6() {
		ipLen = ipv6HeaderLen
	}
	require.Len(t, frame, ethHeaderLen+ipLen+tcpHeaderLen, "RST length")
	assert.Equal(t, clientMAC, frame[0:6], "destination MAC: the host veth")
	assert.Equal(t, podMAC, frame[6:12], "source MAC: the pod")

	ip, tcp := frame[ethHeaderLen:ethHeaderLen+ipLen], frame[ethHeaderLen+ipLen:]
	var src, dst netip.Addr
	if syn.src.Addr().Is4() {
		assert.Equal(t, uint16(ethTypeIPv4), binary.BigEndian.Uint16(frame[12:]))
		assert.Equal(t, byte(0x45), ip[0], "version and header length")
		assert.Equal(t, uint16(ipv4HeaderLen+tcpHeaderLen), binary.BigEndian.Uint16(ip[2:]), "total length")
		assert.Equal(t, byte(ipProtoTCP), ip[9])
		assert.Zero(t, ^onesComplementSum(0, ip), "IPv4 header checksum")
		src, _ = netip.AddrFromSlice(ip[12:16])
		dst, _ = netip.AddrFromSlice(ip[16:20])
	} else {
		assert.Equal(t, uint16(ethTypeIPv6), binary.BigEndian.Uint16(frame[12:]))
		assert.Equal(t, byte(0x60), ip[0], "version")
		assert.Equal(t, uint16(tcpHeaderLen), binary.BigEndian.Uint16(ip[4:]), "payload length")
		assert.Equal(t, byte(ipProtoTCP), ip[6])
		src, _ = netip.AddrFromSlice(ip[8:24])
		dst, _ = netip.AddrFromSlice(ip[24:40])
	}
	assert.Equal(t, syn.dst.Addr(), src, "source: the pod")
	assert.Equal(t, syn.src.Addr(), dst, "destination: the client")
	assert.Equal(t, syn.dst.Port(), binary.BigEndian.Uint16(tcp[0:]), "source port")
	assert.Equal(t, syn.src.Port(), binary.BigEndian.Uint16(tcp[2:]), "destination port")
	assert.Zero(t, binary.BigEndian.Uint32(tcp[4:]), "seq")
	assert.Equal(t, syn.seq+1, binary.BigEndian.Uint32(tcp[8:]), "ack")
	assert.Equal(t, byte(tcpHeaderLen/4)<<4, tcp[12], "data offset")
	assert.Equal(t, byte(tcpFlagRst|tcpFlagAck), tcp[13], "flags")
	assert.Zero(t, ^onesComplementSum(uint32(onesComplementSum(0, pseudoHeader(src, dst, len(tcp)))), tcp), "TCP checksum")
}

// pseudoHeader is the part of the TCP checksum input that comes from the IP
// header (RFC 9293 3.1 for IPv4, RFC 8200 8.1 for IPv6).
func pseudoHeader(src, dst netip.Addr, tcpLen int) []byte {
	pseudo := append(src.AsSlice(), dst.AsSlice()...)
	if src.Is4() {
		pseudo = append(pseudo, 0, ipProtoTCP)
		return binary.BigEndian.AppendUint16(pseudo, uint16(tcpLen))
	}
	pseudo = binary.BigEndian.AppendUint32(pseudo, uint32(tcpLen))
	return append(pseudo, 0, 0, 0, ipProtoTCP)
}

// countEntries is how the tests see what the programs left in a map: that the
// pending RST was consumed, and that no flow was recorded for it.
func countEntries(t *testing.T, m goebpfmaps.BpfMap) int {
	t.Helper()
	keys, err := m.GetAllMapKeys()
	require.NoError(t, err)
	return len(keys)
}

func TestTCPResetOnDenyKernel(t *testing.T) {
	dir := requireBPFKernelTests(t)
	families := []struct {
		name          string
		v6            bool
		client, pod   netip.AddrPort
		ingressBinary string
		ctDenyBinary  string
	}{
		{"v4", false, netip.MustParseAddrPort("10.0.0.1:40000"), netip.MustParseAddrPort("10.0.1.2:80"),
			TC_INGRESS_BINARY, TC_INGRESS_CT_DENY_BINARY},
		{"v6", true, netip.MustParseAddrPort("[fd00::1]:40000"), netip.MustParseAddrPort("[fd00:1::2]:80"),
			TC_V6_INGRESS_BINARY, TC_V6_INGRESS_CT_DENY_BINARY},
	}
	for _, fam := range families {
		variants := []string{fam.ingressBinary}
		if err := checkKfuncs(ctDenyKfuncs); err == nil {
			variants = append(variants, fam.ctDenyBinary)
		} else if bpfKernelTestsRequired() {
			// nf_conntrack registers the kfuncs when it loads, and the CI
			// runner's kernel has them (both ct-deny variants run there), so
			// in CI their absence means the module isn't loaded, not a kernel
			// without them. Skipping would silently drop half the cases.
			t.Fatalf("%s: kernel lacks the conntrack kfuncs (modprobe nf_conntrack): %v", fam.ctDenyBinary, err)
		} else {
			t.Logf("skipping %s: kernel lacks the conntrack kfuncs: %v", fam.ctDenyBinary, err)
		}
		for _, ingressBinary := range variants {
			t.Run(fam.name+"/"+ingressBinary, func(t *testing.T) {
				progs := loadFamily(t, dir, fam.v6, ingressBinary)
				syn := tcpSegment{src: fam.client, dst: fam.pod, seq: 0x11223344, flags: tcpFlagSyn,
					options: make([]byte, synOptionsLen)}

				t.Run("flag off: denied SYN dropped", func(t *testing.T) {
					require.NoError(t, writeTCConfig(progs.config, false))
					verdict, out := testRun(t, progs.ingressFD, syn.packet())
					assert.Equal(t, uint32(tcActShot), verdict)
					assert.Equal(t, syn.packet(), out, "packet unchanged")
					assert.Zero(t, countEntries(t, progs.pending))
				})

				require.NoError(t, writeTCConfig(progs.config, true))
				t.Run("flag on: denied SYN answered with RST", func(t *testing.T) {
					verdict, rst := testRun(t, progs.ingressFD, syn.packet())
					require.Equal(t, uint32(tcActRedirect), verdict)
					assertReset(t, syn, rst)
					assert.Equal(t, 1, countEntries(t, progs.pending), "RST recorded for the egress program")

					// The pod's egress policy denies everything, yet the
					// RST passes, and leaves no flow that would let the
					// client's next SYN in as a reply.
					verdict, _ = testRun(t, progs.egressFD, rst)
					assert.Equal(t, uint32(tcActOK), verdict, "egress passes the RST")
					assert.Zero(t, countEntries(t, progs.pending), "egress consumed the entry")
					assert.Zero(t, countEntries(t, progs.conntrack), "no flow recorded")

					verdict, _ = testRun(t, progs.egressFD, rst)
					assert.Equal(t, uint32(tcActShot), verdict, "a second identical RST is the pod's own and is denied")
				})

				t.Run("flag on: SYN on a flow the policy no longer allows answered with RST", func(t *testing.T) {
					// The ingress program has a second deny path: a SYN on a
					// flow it recorded under an earlier policy state, such as a
					// retransmit after a policy change, is evaluated again. A
					// recorded flow whose state differs from the pod's current
					// one takes that path.
					ifindex := testRunIfindex(t, progs, syn)
					recordStaleFlow(t, progs.conntrack, syn, ifindex)

					verdict, rst := testRun(t, progs.ingressFD, syn.packet())
					require.Equal(t, uint32(tcActRedirect), verdict)
					assertReset(t, syn, rst)
					assert.Zero(t, countEntries(t, progs.conntrack), "the stale flow is removed")
					verdict, _ = testRun(t, progs.egressFD, rst)
					assert.Equal(t, uint32(tcActOK), verdict, "egress passes the RST")
				})

				// Only a bare SYN is answered. Each segment here fails exactly
				// one of its conditions, so each catches that one being dropped.
				for _, tc := range []struct {
					name  string
					flags uint8
				}{
					{"segment without SYN", 0},
					{"SYN-ACK", tcpFlagSyn | tcpFlagAck},
					{"SYN-FIN", tcpFlagSyn | tcpFlagFin},
					{"SYN-RST", tcpFlagSyn | tcpFlagRst},
				} {
					t.Run("flag on: denied "+tc.name+" dropped", func(t *testing.T) {
						segment := syn
						segment.flags = tc.flags
						verdict, out := testRun(t, progs.ingressFD, segment.packet())
						assert.Equal(t, uint32(tcActShot), verdict)
						assert.Equal(t, segment.packet(), out, "packet unchanged")
					})
				}

				// Last: the allowed SYN records a flow, which later packets
				// of the same 5-tuple would match.
				t.Run("flag on: allowed SYN passed unchanged", func(t *testing.T) {
					// Every other case is denied, so without this one, a
					// RST for every SYN would pass them all.
					writePodState(t, progs.ingressPodState, POD_STATE_MAP_KEY, DEFAULT_ALLOW)
					verdict, out := testRun(t, progs.ingressFD, syn.packet())
					assert.Equal(t, uint32(tcActOK), verdict)
					assert.Equal(t, syn.packet(), out, "packet unchanged")
					assert.Zero(t, countEntries(t, progs.pending), "no RST pending")
				})
			})
		}
	}
}

// testRunIfindex returns the ifindex BPF_PROG_TEST_RUN gives the packet, which
// the programs put in their flow and pending keys. It is read from the pending
// entry of one RST, which is then consumed so the map is empty again.
func testRunIfindex(t *testing.T, progs loadedFamily, syn tcpSegment) uint32 {
	t.Helper()
	verdict, rst := testRun(t, progs.ingressFD, syn.packet())
	require.Equal(t, uint32(tcActRedirect), verdict)
	keys, err := progs.pending.GetAllMapKeys()
	require.NoError(t, err)
	require.Len(t, keys, 1)
	key := []byte(keys[0])
	ifindex := binary.NativeEndian.Uint32(key[len(key)-4:])
	verdict, _ = testRun(t, progs.egressFD, rst)
	require.Equal(t, uint32(tcActOK), verdict)
	return ifindex
}

// staleFlowState is a policy state value no pod state produces, so a flow
// recorded with it always differs from the pod's current state.
const staleFlowState = 0xff

// recordStaleFlow records syn's flow in the conntrack map the way the ingress
// program would have when it allowed it, but with staleFlowState.
func recordStaleFlow(t *testing.T, conntrack goebpfmaps.BpfMap, syn tcpSegment, ifindex uint32) {
	t.Helper()
	value := utils.ConntrackVal{Value: staleFlowState}
	src, dst := syn.src.Addr(), syn.dst.Addr()
	var err error
	if src.Is4() {
		// The programs store IPv4 addresses as the raw network-order bytes
		// loaded into a native u32, and ports in host order.
		s, d := src.As4(), dst.As4()
		key := utils.ConntrackKey{
			Source_ip: binary.NativeEndian.Uint32(s[:]), Source_port: syn.src.Port(),
			Dest_ip: binary.NativeEndian.Uint32(d[:]), Dest_port: syn.dst.Port(),
			Protocol: ipProtoTCP, Owner_ip: binary.NativeEndian.Uint32(d[:]), Ifindex: ifindex,
		}
		err = conntrack.CreateUpdateMapEntry(uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(&value)), 0)
	} else {
		key := utils.ConntrackKeyV6{
			Source_ip: src.As16(), Source_port: syn.src.Port(),
			Dest_ip: dst.As16(), Dest_port: syn.dst.Port(),
			Protocol: ipProtoTCP, Owner_ip: dst.As16(), Ifindex: ifindex,
		}
		err = conntrack.CreateUpdateMapEntry(uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(&value)), 0)
	}
	require.NoError(t, err)
}
