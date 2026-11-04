package conntrack

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// nlaTypeMask strips NLA_F_NESTED from an attribute type. It is the mask
// netlink's own conntrack parser applies, which keeps NLA_F_NET_BYTEORDER, so an
// attribute with that flag is not recognized here either. ctnetlink does not set
// it on the tuple attributes.
const nlaTypeMask = nl.NLA_F_NESTED - 1

// flowLookup looks up single flows in the kernel conntrack table.
type flowLookup interface {
	// lookup asks the kernel for the flow that has tpl as one of its tuples and
	// fills flow with it. dir is nl.CTA_TUPLE_ORIG or nl.CTA_TUPLE_REPLY. The
	// kernel ignores dir when it searches: its conntrack hash holds both tuples
	// of every flow and a tuple belongs to at most one flow per zone, so either
	// direction finds the flow that has tpl as its original or its reply tuple.
	// The search covers the default conntrack zone only. found is false if no
	// flow has tpl. Any other failure is returned as an error.
	lookup(dir int, tpl *netlink.IPTuple, flow *netlink.ConntrackFlow) (found bool, err error)
	close()
}

// openFlowLookup opens a flowLookup for a family. It is a variable so unit
// tests can answer lookups from synthetic flows.
var openFlowLookup = openNetlinkFlowLookup

// netlinkFlowLookup sends ctnetlink GET requests over one netlink socket, so a
// cleanup cycle opens a single socket however many entries it looks up.
type netlinkFlowLookup struct {
	family netlink.InetFamily
	socket *nl.SocketHandle
}

func openNetlinkFlowLookup(family netlink.InetFamily) (flowLookup, error) {
	s, err := nl.GetNetlinkSocketAt(netns.None(), netns.None(), unix.NETLINK_NETFILTER)
	if err != nil {
		return nil, err
	}
	// ExecuteIter sets these timeouts only on the sockets it opens itself.
	if err := s.SetSendTimeout(&nl.SocketTimeoutTv); err != nil {
		s.Close()
		return nil, err
	}
	if err := s.SetReceiveTimeout(&nl.SocketTimeoutTv); err != nil {
		s.Close()
		return nil, err
	}
	return &netlinkFlowLookup{family: family, socket: &nl.SocketHandle{Socket: s}}, nil
}

func (l *netlinkFlowLookup) lookup(dir int, tpl *netlink.IPTuple, flow *netlink.ConntrackFlow) (bool, error) {
	req := newFlowGetRequest(l.family, dir, tpl)
	req.Sockets = map[int]*nl.SocketHandle{unix.NETLINK_NETFILTER: l.socket}
	var parseErr error
	got := false
	// The ACK is consumed by ExecuteIter, so the callback sees only the flow.
	err := req.ExecuteIter(unix.NETLINK_NETFILTER, 0, func(msg []byte) bool {
		parseErr = parseConntrackFlow(msg, flow)
		got = true
		return false
	})
	if errors.Is(err, unix.ENOENT) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if parseErr != nil {
		return false, parseErr
	}
	if !got {
		return false, errors.New("conntrack get returned no flow")
	}
	return true, nil
}

func (l *netlinkFlowLookup) close() {
	l.socket.Close()
}

// newFlowGetRequest builds a ctnetlink IPCTNL_MSG_CT_GET request for the flow
// with tuple tpl. dir is nl.CTA_TUPLE_ORIG or nl.CTA_TUPLE_REPLY and names the
// attribute that carries the tuple. The tuple attributes are the ones netlink's
// unexported IPTuple.toNlData builds. The request has no CTA_ZONE, so the
// kernel looks in the default zone.
//
// The kernel sends the flow with NLM_F_MULTI set and no NLMSG_DONE after it,
// so ExecuteIter would wait for more messages until the socket times out. The
// request sets NLM_F_ACK so that an ACK follows the flow and ends the exchange.
// When no flow has the tuple, the only reply is an ENOENT error.
func newFlowGetRequest(family netlink.InetFamily, dir int, tpl *netlink.IPTuple) *nl.NetlinkRequest {
	req := nl.NewNetlinkRequest((int(netlink.ConntrackTable)<<8)|nl.IPCTNL_MSG_CT_GET, unix.NLM_F_ACK)
	req.AddData(&nl.Nfgenmsg{
		NfgenFamily: uint8(family),
		Version:     nl.NFNETLINK_V0,
		ResId:       0,
	})

	srcIPType, dstIPType := nl.CTA_IP_V4_SRC, nl.CTA_IP_V4_DST
	srcIP, dstIP := tpl.SrcIP.To4(), tpl.DstIP.To4()
	if family == unix.AF_INET6 {
		srcIPType, dstIPType = nl.CTA_IP_V6_SRC, nl.CTA_IP_V6_DST
		srcIP, dstIP = tpl.SrcIP.To16(), tpl.DstIP.To16()
	}
	tuple := nl.NewRtAttr(unix.NLA_F_NESTED|dir, nil)
	tupleIP := tuple.AddRtAttr(unix.NLA_F_NESTED|nl.CTA_TUPLE_IP, nil)
	tupleIP.AddRtAttr(srcIPType, srcIP)
	tupleIP.AddRtAttr(dstIPType, dstIP)
	tupleProto := tuple.AddRtAttr(unix.NLA_F_NESTED|nl.CTA_TUPLE_PROTO, nil)
	tupleProto.AddRtAttr(nl.CTA_PROTO_NUM, []byte{tpl.Protocol})
	tupleProto.AddRtAttr(nl.CTA_PROTO_SRC_PORT, nl.BEUint16Attr(tpl.SrcPort))
	tupleProto.AddRtAttr(nl.CTA_PROTO_DST_PORT, nl.BEUint16Attr(tpl.DstPort))
	req.AddData(tuple)
	return req
}

// ctnetlink attributes from linux/netfilter/nfnetlink_conntrack.h that nl does
// not define, and the CTA_FILTER flag for the protocol number from
// net/netfilter/nf_internals.h.
const (
	ctaFilter             = 25     // CTA_FILTER
	ctaFilterOrigFlags    = 1      // CTA_FILTER_ORIG_FLAGS
	ctaFilterFlagProtoNum = 1 << 3 // CTA_FILTER_F_CTA_PROTO_NUM
)

// dumpProtocolFlows streams the kernel conntrack flows of one family and L4
// protocol. It is a variable so unit tests can feed synthetic flows.
var dumpProtocolFlows = streamProtocolFlows

// streamProtocolFlows dumps the kernel conntrack flows of family whose original
// tuple has L4 protocol protocol, and calls fn once per flow as the netlink
// messages arrive. The flow passed to fn is reused between calls and its IPs
// point into the receive buffer, so fn must not keep it.
//
// The request asks the kernel to filter the dump by protocol with CTA_FILTER,
// which ctnetlink supports since Linux 5.8. The kernel then sends only the
// matching flows, from every conntrack zone since the request has no CTA_ZONE.
// Older kernels ignore the attribute and send the whole family. That is still
// correct, only slower: keys built from other protocols' flows carry their own
// protocol, so they match no entry of this one. If the kernel flagged the dump
// as inconsistent, it returns netlink.ErrDumpInterrupted.
func streamProtocolFlows(family netlink.InetFamily, protocol uint8, fn func(flow *netlink.ConntrackFlow)) error {
	req := newProtocolDumpRequest(family, protocol)
	var flow netlink.ConntrackFlow
	var parseErr error
	err := req.ExecuteIter(unix.NETLINK_NETFILTER, 0, func(msg []byte) bool {
		if parseErr = parseConntrackFlow(msg, &flow); parseErr != nil {
			// Stop calling fn. ExecuteIter drains the rest of the dump.
			return false
		}
		fn(&flow)
		return true
	})
	if err != nil {
		return err
	}
	return parseErr
}

// newProtocolDumpRequest builds a ctnetlink IPCTNL_MSG_CT_GET dump request for
// the flows of family whose original tuple has L4 protocol protocol. The
// nfgenmsg family limits the dump to the family, and CTA_FILTER with
// CTA_FILTER_ORIG_FLAGS set to CTA_FILTER_F_CTA_PROTO_NUM tells the kernel to
// compare only the protocol number of the CTA_TUPLE_ORIG that follows.
func newProtocolDumpRequest(family netlink.InetFamily, protocol uint8) *nl.NetlinkRequest {
	req := nl.NewNetlinkRequest((int(netlink.ConntrackTable)<<8)|nl.IPCTNL_MSG_CT_GET, unix.NLM_F_DUMP)
	req.AddData(&nl.Nfgenmsg{
		NfgenFamily: uint8(family),
		Version:     nl.NFNETLINK_V0,
		ResId:       0,
	})
	tuple := nl.NewRtAttr(unix.NLA_F_NESTED|nl.CTA_TUPLE_ORIG, nil)
	tupleProto := tuple.AddRtAttr(unix.NLA_F_NESTED|nl.CTA_TUPLE_PROTO, nil)
	tupleProto.AddRtAttr(nl.CTA_PROTO_NUM, []byte{protocol})
	req.AddData(tuple)
	filter := nl.NewRtAttr(unix.NLA_F_NESTED|ctaFilter, nil)
	filter.AddRtAttr(ctaFilterOrigFlags, nl.Uint32Attr(ctaFilterFlagProtoNum))
	req.AddData(filter)
	return req
}

// parseConntrackFlow fills flow with the fields the conntrack GC uses: family,
// and the source and destination IPs, ports and L4 protocol of the original and
// reply tuples. It matches netlink's parser for those fields, including leaving
// the ports at zero for protocols other than TCP and UDP. A message without
// both tuples is an error, so the caller skips the cycle instead of treating
// entries as stale. The IPs in flow point into msg.
func parseConntrackFlow(msg []byte, flow *netlink.ConntrackFlow) error {
	*flow = netlink.ConntrackFlow{}
	if len(msg) < nl.SizeofNfgenmsg {
		return fmt.Errorf("conntrack message too short: %d bytes", len(msg))
	}
	flow.FamilyType = msg[0]
	attrs, err := nl.ParseRouteAttr(msg[nl.SizeofNfgenmsg:])
	if err != nil {
		return fmt.Errorf("parse conntrack attributes: %v", err)
	}
	var haveOrig, haveReply bool
	for _, attr := range attrs {
		// netlink's parser only reads the tuples from nested attributes.
		if attr.Attr.Type&unix.NLA_F_NESTED == 0 {
			continue
		}
		switch attr.Attr.Type & nlaTypeMask {
		case nl.CTA_TUPLE_ORIG:
			if err := parseConntrackTuple(attr.Value, &flow.Forward); err != nil {
				return fmt.Errorf("parse original tuple: %v", err)
			}
			haveOrig = true
		case nl.CTA_TUPLE_REPLY:
			if err := parseConntrackTuple(attr.Value, &flow.Reverse); err != nil {
				return fmt.Errorf("parse reply tuple: %v", err)
			}
			haveReply = true
		}
	}
	if !haveOrig || !haveReply {
		return errors.New("conntrack message is missing the original or reply tuple")
	}
	return nil
}

// parseConntrackTuple parses the CTA_TUPLE_IP and CTA_TUPLE_PROTO attributes of
// a CTA_TUPLE_ORIG or CTA_TUPLE_REPLY payload.
func parseConntrackTuple(b []byte, tpl *netlink.IPTuple) error {
	attrs, err := nl.ParseRouteAttr(b)
	if err != nil {
		return err
	}
	var srcPort, dstPort uint16
	for _, attr := range attrs {
		switch attr.Attr.Type & nlaTypeMask {
		case nl.CTA_TUPLE_IP:
			ipAttrs, err := nl.ParseRouteAttr(attr.Value)
			if err != nil {
				return err
			}
			for _, ipAttr := range ipAttrs {
				switch ipAttr.Attr.Type & nlaTypeMask {
				case nl.CTA_IP_V4_SRC, nl.CTA_IP_V6_SRC:
					tpl.SrcIP = net.IP(ipAttr.Value)
				case nl.CTA_IP_V4_DST, nl.CTA_IP_V6_DST:
					tpl.DstIP = net.IP(ipAttr.Value)
				}
			}
		case nl.CTA_TUPLE_PROTO:
			protoAttrs, err := nl.ParseRouteAttr(attr.Value)
			if err != nil {
				return err
			}
			for _, protoAttr := range protoAttrs {
				switch protoAttr.Attr.Type & nlaTypeMask {
				case nl.CTA_PROTO_NUM:
					if len(protoAttr.Value) < 1 {
						return errors.New("empty CTA_PROTO_NUM")
					}
					tpl.Protocol = protoAttr.Value[0]
				case nl.CTA_PROTO_SRC_PORT:
					if len(protoAttr.Value) < 2 {
						return errors.New("short CTA_PROTO_SRC_PORT")
					}
					srcPort = binary.BigEndian.Uint16(protoAttr.Value)
				case nl.CTA_PROTO_DST_PORT:
					if len(protoAttr.Value) < 2 {
						return errors.New("short CTA_PROTO_DST_PORT")
					}
					dstPort = binary.BigEndian.Uint16(protoAttr.Value)
				}
			}
		}
	}
	if len(tpl.SrcIP) == 0 || len(tpl.DstIP) == 0 {
		return errors.New("tuple is missing an IP address")
	}
	// netlink's parser reads ports for TCP and UDP only.
	if tpl.Protocol == unix.IPPROTO_TCP || tpl.Protocol == unix.IPPROTO_UDP {
		tpl.SrcPort = srcPort
		tpl.DstPort = dstPort
	}
	return nil
}
