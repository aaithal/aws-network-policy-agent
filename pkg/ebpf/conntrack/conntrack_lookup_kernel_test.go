package conntrack

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

// These tests run the netlink lookup and dump against a real kernel, using the
// namespace setup in conntrack_gc_kernel_test.go.

// testFamilies are the address families the tests run for, with the shared
// addresses of each.
var testFamilies = []struct {
	name                    string
	v6                      bool
	family                  netlink.InetFamily
	podA, podB, vip, remote string
}{
	{"v4", false, unix.AF_INET, podA, podB, vip, remote},
	{"v6", true, unix.AF_INET6, podA6, podB6, vip6, remote6},
}

// createFlowInZone adds flow to conntrack zone zone. netlink.ConntrackCreate
// sends no CTA_ZONE, so this sends the request it builds with CTA_ZONE added.
func createFlowInZone(t *testing.T, flow *netlink.ConntrackFlow, zone uint16) {
	t.Helper()
	req := nl.NewNetlinkRequest((int(netlink.ConntrackTable)<<8)|nl.IPCTNL_MSG_CT_NEW, unix.NLM_F_ACK|unix.NLM_F_CREATE)
	req.AddData(&nl.Nfgenmsg{NfgenFamily: flow.FamilyType, Version: nl.NFNETLINK_V0})
	for _, tuple := range []struct {
		dir int
		tpl *netlink.IPTuple
	}{{nl.CTA_TUPLE_ORIG, &flow.Forward}, {nl.CTA_TUPLE_REPLY, &flow.Reverse}} {
		attr := nl.NewRtAttr(unix.NLA_F_NESTED|tuple.dir, nil)
		for _, a := range tupleToNlData(tuple.tpl, flow.FamilyType) {
			attr.AddChild(a)
		}
		req.AddData(attr)
	}
	req.AddData(nl.NewRtAttr(nl.CTA_TIMEOUT, nl.BEUint32Attr(testFlowTimeout)))
	req.AddData(nl.NewRtAttr(nl.CTA_ZONE, nl.BEUint16Attr(zone)))
	_, err := req.Execute(unix.NETLINK_NETFILTER, 0)
	require.NoError(t, err)
}

func TestNetlinkFlowLookupKernel(t *testing.T) {
	for _, fam := range testFamilies {
		t.Run(fam.name, func(t *testing.T) {
			enterTestNetns(t)
			plain := testFlow(fam.v6, protoTCP, fam.podA, 40000, fam.remote, 443, fam.remote, 443)
			dnat := testFlow(fam.v6, protoUDP, fam.podA, 40001, fam.vip, 53, fam.podB, 5353)
			zoned := testFlow(fam.v6, protoTCP, fam.podA, 40002, fam.remote, 443, fam.remote, 443)
			missing := testFlow(fam.v6, protoTCP, fam.podA, 40003, fam.remote, 443, fam.remote, 443)
			createFlow(t, plain)
			createFlow(t, dnat)
			createFlowInZone(t, zoned, 5)

			lookup, err := openNetlinkFlowLookup(fam.family)
			require.NoError(t, err)
			defer lookup.close()

			// Every case below is a GET on the one socket. The socket stays in
			// the namespace it was opened in, so subtests can use it from any
			// thread.
			cases := []struct {
				name string
				dir  int
				tpl  netlink.IPTuple
				want *netlink.ConntrackFlow
			}{
				{"original tuple", nl.CTA_TUPLE_ORIG, plain.Forward, plain},
				{"reply tuple of a DNAT'd flow", nl.CTA_TUPLE_REPLY, dnat.Reverse, dnat},
				{"missing tuple", nl.CTA_TUPLE_ORIG, missing.Forward, nil},
				{"flow in a non-default zone is not found", nl.CTA_TUPLE_ORIG, zoned.Forward, nil},
				{"original tuple of a DNAT'd flow", nl.CTA_TUPLE_ORIG, dnat.Forward, dnat},
				{"reply tuple", nl.CTA_TUPLE_REPLY, plain.Reverse, plain},
			}
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					var got netlink.ConntrackFlow
					found, err := lookup.lookup(tc.dir, &tc.tpl, &got)
					require.NoError(t, err)
					require.Equal(t, tc.want != nil, found, "found")
					if tc.want != nil {
						assert.Equal(t, tc.want.FamilyType, got.FamilyType)
						assert.True(t, tupleEqual(&tc.want.Forward, &got.Forward), "forward: %v", got.Forward)
						assert.True(t, tupleEqual(&tc.want.Reverse, &got.Reverse), "reverse: %v", got.Reverse)
					}
				})
			}
		})
	}
}

// TestStreamProtocolFlowsKernel dumps GRE flows, which the GC matches by dump
// like ICMP ones, from a table that also has TCP and UDP flows.
// netlink.ConntrackCreate cannot create ICMP flows: it sends ports, and the
// kernel needs the ICMP id, type and code.
func TestStreamProtocolFlowsKernel(t *testing.T) {
	for _, fam := range testFamilies {
		t.Run(fam.name, func(t *testing.T) {
			enterTestNetns(t)
			a, b, r := fam.podA, fam.podB, fam.remote
			createFlow(t, testFlow(fam.v6, protoTCP, a, 40000, r, 443, r, 443))
			createFlow(t, testFlow(fam.v6, protoUDP, a, 40001, r, 53, r, 53))
			createFlow(t, testFlow(fam.v6, protoGRE, a, 0, r, 0, r, 0))
			createFlow(t, testFlow(fam.v6, protoTCP, b, 40002, r, 443, r, 443))
			createFlow(t, testFlow(fam.v6, protoGRE, b, 0, r, 0, r, 0))

			var got []string
			err := streamProtocolFlows(fam.family, protoGRE, func(flow *netlink.ConntrackFlow) {
				assert.Equal(t, protoGRE, flow.Forward.Protocol)
				got = append(got, flow.Forward.SrcIP.String()+" -> "+flow.Forward.DstIP.String())
			})
			require.NoError(t, err)
			assert.ElementsMatch(t, []string{a + " -> " + r, b + " -> " + r}, got)
		})
	}
}
