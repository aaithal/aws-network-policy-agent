package conntrack

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

// fakeKernel answers the GC's kernel reads from synthetic flows, which hold
// ports the way netlink reports them, zero for protocols other than TCP and
// UDP.
//
// A lookup behaves like a ctnetlink GET: it finds the flow that has the tuple as
// its original or reply tuple, in the default zone only. A protocol dump
// behaves like a dump filtered by protocol: it returns that protocol's flows
// from every zone.
//
// If readErr is set, every lookup and dump fails with it, except that
// netlink.ErrDumpInterrupted fails dumps only, after returning their flows,
// since the kernel flags only dumps as interrupted.
type fakeKernel struct {
	t       *testing.T
	family  netlink.InetFamily
	flows   []*netlink.ConntrackFlow
	readErr error

	// failLookupAt is the 1-based lookup that returns failLookupErr, or 0 for
	// none.
	failLookupAt  int
	failLookupErr error
	openErr       error

	lookups int
	dumps   []uint8
	opened  bool
	closed  bool
}

func tupleEqual(a, b *netlink.IPTuple) bool {
	return a.SrcIP.Equal(b.SrcIP) && a.DstIP.Equal(b.DstIP) &&
		a.SrcPort == b.SrcPort && a.DstPort == b.DstPort && a.Protocol == b.Protocol
}

func (k *fakeKernel) failsAll() bool {
	return k.readErr != nil && !errors.Is(k.readErr, netlink.ErrDumpInterrupted)
}

func (k *fakeKernel) lookup(dir int, tpl *netlink.IPTuple, flow *netlink.ConntrackFlow) (bool, error) {
	k.lookups++
	assert.Contains(k.t, []int{nl.CTA_TUPLE_ORIG, nl.CTA_TUPLE_REPLY}, dir)
	assert.Equal(k.t, k.family == unix.AF_INET, tpl.SrcIP.To4() != nil, "tuple IP family")
	// Only TCP and UDP tuples carry everything a GET needs.
	assert.Contains(k.t, []uint8{unix.IPPROTO_TCP, unix.IPPROTO_UDP}, tpl.Protocol, "lookup protocol")
	if k.failLookupAt == k.lookups {
		return false, k.failLookupErr
	}
	if k.failsAll() {
		return false, k.readErr
	}
	for _, c := range k.flows {
		if c.Zone != 0 {
			continue
		}
		if tupleEqual(&c.Forward, tpl) || tupleEqual(&c.Reverse, tpl) {
			*flow = *c
			return true, nil
		}
	}
	return false, nil
}

func (k *fakeKernel) close() {
	k.closed = true
}

func (k *fakeKernel) dump(family netlink.InetFamily, protocol uint8, fn func(flow *netlink.ConntrackFlow)) error {
	assert.Equal(k.t, k.family, family)
	assert.NotContains(k.t, k.dumps, protocol, "protocol dumped twice")
	k.dumps = append(k.dumps, protocol)
	if k.failsAll() {
		return k.readErr
	}
	for _, c := range k.flows {
		if c.Forward.Protocol == protocol {
			f := *c
			fn(&f)
		}
	}
	return k.readErr
}

// withKernelFlows makes the GC read flows as the kernel conntrack table for
// family. If readErr is set, reading the table fails with it, as described on
// fakeKernel.
func withKernelFlows(t *testing.T, family netlink.InetFamily, flows []*netlink.ConntrackFlow, readErr error) *fakeKernel {
	// A tuple belongs to at most one flow per zone. Check the fixture keeps to
	// that, or the answers would depend on flow order.
	for i, a := range flows {
		for _, b := range flows[i+1:] {
			if a.Zone != b.Zone {
				continue
			}
			for _, ta := range []*netlink.IPTuple{&a.Forward, &a.Reverse} {
				for _, tb := range []*netlink.IPTuple{&b.Forward, &b.Reverse} {
					require.False(t, tupleEqual(ta, tb), "two flows share a tuple")
				}
			}
		}
	}
	k := &fakeKernel{t: t, family: family, flows: flows, readErr: readErr}
	origOpen, origDump := openFlowLookup, dumpProtocolFlows
	t.Cleanup(func() {
		openFlowLookup, dumpProtocolFlows = origOpen, origDump
		if k.opened {
			assert.True(t, k.closed, "lookup must be closed")
		}
	})
	openFlowLookup = func(fam netlink.InetFamily) (flowLookup, error) {
		assert.Equal(t, family, fam)
		if k.openErr != nil {
			return nil, k.openErr
		}
		k.opened = true
		return k, nil
	}
	dumpProtocolFlows = k.dump
	return k
}
