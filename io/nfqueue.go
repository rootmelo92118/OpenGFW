package io

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/coreos/go-iptables/iptables"
	"github.com/florianl/go-nfqueue"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

const (
	nfqueueDefaultQueueNum  = 100
	nfqueueMaxPacketLen     = 0xFFFF
	nfqueueDefaultQueueSize = 128

	nfqueueDefaultConnMarkAccept = 1001

	nftFamily       = "inet"
	nftDefaultTable = "opengfw"
)

// EnabledChainsConfig specifies which netfilter chains to attach to.
// If all fields are false and Local is also false, defaults to Forward=true.
type EnabledChainsConfig struct {
	Input   bool
	Output  bool
	Forward bool
}

// activeChains resolves the final list of chains to use.
// Priority: Docker > EnabledChains explicit > default (Forward only)
func activeChains(chains EnabledChainsConfig, docker bool) []chainEntry {
	// Docker mode: intercept both host-level input and container forwarded traffic
	if docker {
		return []chainEntry{
			{chain: "INPUT"},
			{chain: "FORWARD"},
		}
	}

	// Explicit per-chain flags
	if chains.Input || chains.Output || chains.Forward {
		var result []chainEntry
		if chains.Input {
			result = append(result, chainEntry{chain: "INPUT"})
		}
		if chains.Output {
			result = append(result, chainEntry{chain: "OUTPUT"})
		}
		if chains.Forward {
			result = append(result, chainEntry{chain: "FORWARD"})
		}
		return result
	}

	// Default: Forward only
	return []chainEntry{
		{chain: "FORWARD"},
	}
}

// chainEntry holds a chain name.
type chainEntry struct {
	chain string
}

func (n *nfqueuePacketIO) generateNftRules() (*nftTableSpec, error) {
	entries := activeChains(n.enabledChains, n.docker)

	// RST only makes sense when INPUT is present (so we can reject inbound SYNs)
	if n.rst {
		inputPresent := false
		for _, c := range entries {
			if c.chain == "INPUT" {
				inputPresent = true
				break
			}
		}
		if !inputPresent {
			return nil, errors.New("tcp rst requires INPUT chain to be enabled")
		}
	}

	table := &nftTableSpec{
		Family: nftFamily,
		Table:  n.table,
	}
	table.Defines = append(table.Defines, fmt.Sprintf("define ACCEPT_CTMARK=%d", n.connMarkAccept))
	table.Defines = append(table.Defines, fmt.Sprintf("define DROP_CTMARK=%d", n.connMarkDrop))
	table.Defines = append(table.Defines, fmt.Sprintf("define QUEUE_NUM=%d", n.queueNum))

	chainHeaders := map[string]string{
		"INPUT":   "type filter hook input priority filter; policy accept;",
		"OUTPUT":  "type filter hook output priority filter; policy accept;",
		"FORWARD": "type filter hook forward priority filter; policy accept;",
	}

	for _, entry := range entries {
		spec := nftChainSpec{
			Chain:  entry.chain,
			Header: chainHeaders[entry.chain],
		}
		// Restrict mark-based bypass to established/related flows on all chains.
		// This prevents external mark modifications (Docker, eBPF, policy routing)
		// from silently bypassing NFQUEUE for NEW connections.
		spec.Rules = append(spec.Rules, "ct state established,related meta mark $ACCEPT_CTMARK ct mark set $ACCEPT_CTMARK") // Bypass protected connections
		spec.Rules = append(spec.Rules, "ct state established,related ct mark $ACCEPT_CTMARK counter accept")
		if n.rst {
			spec.Rules = append(spec.Rules, "ct state established,related ip protocol tcp ct mark $DROP_CTMARK counter reject with tcp reset")
		}
		spec.Rules = append(spec.Rules, "ct state established,related ct mark $DROP_CTMARK counter drop")
		spec.Rules = append(spec.Rules, "counter queue num $QUEUE_NUM bypass")
		table.Chains = append(table.Chains, spec)
	}

	return table, nil
}

func (n *nfqueuePacketIO) generateIptRules() ([]iptRule, error) {
	entries := activeChains(n.enabledChains, n.docker)

	if n.rst {
		inputPresent := false
		for _, c := range entries {
			if c.chain == "INPUT" {
				inputPresent = true
				break
			}
		}
		if !inputPresent {
			return nil, errors.New("tcp rst requires INPUT chain to be enabled")
		}
	}

	rules := make([]iptRule, 0, 5*len(entries))

	for _, entry := range entries {
		// Restrict mark-based bypass to established/related flows on all chains.
		// This prevents external mark modifications (Docker, eBPF, policy routing)
		// from silently bypassing NFQUEUE for NEW connections.
		rules = append(rules, iptRule{"filter", entry.chain, []string{
			"-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED",
			"-m", "mark", "--mark", strconv.Itoa(n.connMarkAccept),
			"-j", "CONNMARK", "--set-mark", strconv.Itoa(n.connMarkAccept),
		}})
		rules = append(rules, iptRule{"filter", entry.chain, []string{
			"-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED",
			"-m", "connmark", "--mark", strconv.Itoa(n.connMarkAccept),
			"-j", "ACCEPT",
		}})
		if n.rst {
			rules = append(rules, iptRule{"filter", entry.chain, []string{
				"-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED",
				"-p", "tcp",
				"-m", "connmark", "--mark", strconv.Itoa(n.connMarkDrop),
				"-j", "REJECT", "--reject-with", "tcp-reset",
			}})
		}
		rules = append(rules, iptRule{"filter", entry.chain, []string{
			"-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED",
			"-m", "connmark", "--mark", strconv.Itoa(n.connMarkDrop),
			"-j", "DROP",
		}})
		rules = append(rules, iptRule{"filter", entry.chain, []string{
			"-j", "NFQUEUE", "--queue-num", strconv.Itoa(n.queueNum), "--queue-bypass",
		}})
	}

	return rules, nil
}

var _ PacketIO = (*nfqueuePacketIO)(nil)

var errNotNFQueuePacket = errors.New("not an NFQueue packet")

type nfqueuePacketIO struct {
	n              *nfqueue.Nfqueue
	rst            bool
	docker         bool
	enabledChains  EnabledChainsConfig
	rSet           bool // whether the nftables/iptables rules have been set
	queueNum       int
	table          string // nftable name
	connMarkAccept int
	connMarkDrop   int

	// iptables not nil = use iptables instead of nftables
	ipt4 *iptables.IPTables
	ipt6 *iptables.IPTables

	protectedDialer *net.Dialer
}

type NFQueuePacketIOConfig struct {
	QueueSize      uint32
	QueueNum       *uint16
	Table          string
	ConnMarkAccept uint32
	ConnMarkDrop   uint32

	ReadBuffer  int
	WriteBuffer int

	RST bool

	// EnabledChains specifies which netfilter chains to attach to.
	// If all fields are false and Docker is false, defaults to Forward only.
	EnabledChains EnabledChainsConfig

	// Docker mode: intercept INPUT + FORWARD for container traffic.
	// Cannot be combined with EnabledChains.
	Docker bool
}

func NewNFQueuePacketIO(config NFQueuePacketIOConfig) (PacketIO, error) {
	if config.QueueSize == 0 {
		config.QueueSize = nfqueueDefaultQueueSize
	}
	if config.QueueNum == nil {
		queueNum := uint16(nfqueueDefaultQueueNum)
		config.QueueNum = &queueNum
	}
	if config.Table == "" {
		config.Table = nftDefaultTable
	}
	if config.ConnMarkAccept == 0 {
		config.ConnMarkAccept = nfqueueDefaultConnMarkAccept
	}
	if config.ConnMarkDrop == 0 {
		config.ConnMarkDrop = config.ConnMarkAccept + 1
		if config.ConnMarkDrop == 0 {
			// Overflow
			config.ConnMarkDrop = 1
		}
	}
	if config.ConnMarkAccept == config.ConnMarkDrop {
		return nil, errors.New("connMarkAccept and connMarkDrop cannot be the same")
	}

	// Validate: Docker and EnabledChains are mutually exclusive
	if config.Docker && (config.EnabledChains.Input || config.EnabledChains.Output || config.EnabledChains.Forward) {
		return nil, errors.New("docker mode cannot be combined with enabledChains settings")
	}

	var ipt4, ipt6 *iptables.IPTables
	var err error
	if nftCheck() != nil {
		// We prefer nftables, but if it's not available, fall back to iptables
		ipt4, err = iptables.NewWithProtocol(iptables.ProtocolIPv4)
		if err != nil {
			return nil, err
		}
		ipt6, err = iptables.NewWithProtocol(iptables.ProtocolIPv6)
		if err != nil {
			return nil, err
		}
	}
	n, err := nfqueue.Open(&nfqueue.Config{
		NfQueue:      *config.QueueNum,
		MaxPacketLen: nfqueueMaxPacketLen,
		MaxQueueLen:  config.QueueSize,
		Copymode:     nfqueue.NfQnlCopyPacket,
		Flags:        nfqueue.NfQaCfgFlagConntrack,
	})
	if err != nil {
		return nil, err
	}
	if config.ReadBuffer > 0 {
		err = n.Con.SetReadBuffer(config.ReadBuffer)
		if err != nil {
			_ = n.Close()
			return nil, err
		}
	}
	if config.WriteBuffer > 0 {
		err = n.Con.SetWriteBuffer(config.WriteBuffer)
		if err != nil {
			_ = n.Close()
			return nil, err
		}
	}
	return &nfqueuePacketIO{
		n:              n,
		rst:            config.RST,
		docker:         config.Docker,
		enabledChains:  config.EnabledChains,
		queueNum:       int(*config.QueueNum),
		table:          config.Table,
		connMarkAccept: int(config.ConnMarkAccept),
		connMarkDrop:   int(config.ConnMarkDrop),
		ipt4:           ipt4,
		ipt6:           ipt6,
		protectedDialer: &net.Dialer{
			Control: func(network, address string, c syscall.RawConn) error {
				var err error
				cErr := c.Control(func(fd uintptr) {
					err = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, int(config.ConnMarkAccept))
				})
				if cErr != nil {
					return cErr
				}
				return err
			},
		},
	}, nil
}

func (n *nfqueuePacketIO) Register(ctx context.Context, cb PacketCallback) error {
	err := n.n.RegisterWithErrorFunc(ctx,
		func(a nfqueue.Attribute) int {
			if ok, verdict := n.packetAttributeSanityCheck(a); !ok {
				if a.PacketID != nil {
					_ = n.n.SetVerdict(*a.PacketID, verdict)
				}
				return 0
			}
			p := &nfqueuePacket{
				id:       *a.PacketID,
				streamID: ctIDFromCtBytes(*a.Ct),
				data:     *a.Payload,
			}
			// Use timestamp from attribute if available, otherwise use current time as fallback
			if a.Timestamp != nil {
				p.timestamp = *a.Timestamp
			} else {
				p.timestamp = time.Now()
			}
			return okBoolToInt(cb(p, nil))
		},
		func(e error) int {
			if opErr := (*netlink.OpError)(nil); errors.As(e, &opErr) {
				if errors.Is(opErr.Err, unix.ENOBUFS) {
					// Kernel buffer temporarily full, ignore
					return 0
				}
			}
			return okBoolToInt(cb(nil, e))
		})
	if err != nil {
		return err
	}
	if !n.rSet {
		if n.ipt4 != nil {
			err = n.setupIpt(false)
		} else {
			err = n.setupNft(false)
		}
		if err != nil {
			return err
		}
		n.rSet = true
	}
	return nil
}

func (n *nfqueuePacketIO) packetAttributeSanityCheck(a nfqueue.Attribute) (ok bool, verdict int) {
	if a.PacketID == nil {
		// Re-inject to NFQUEUE is actually not possible in this condition
		return false, -1
	}
	if a.Payload == nil || len(*a.Payload) < 20 {
		// 20 is the minimum possible size of an IP packet
		return false, nfqueue.NfDrop
	}
	if a.Ct == nil {
		// Multicast packets may not have a conntrack, but only appear when hooking local input
		if n.enabledChains.Input || n.docker {
			return false, nfqueue.NfAccept
		}
		return false, nfqueue.NfDrop
	}
	return true, -1
}

func (n *nfqueuePacketIO) SetVerdict(p Packet, v Verdict, newPacket []byte) error {
	nP, ok := p.(*nfqueuePacket)
	if !ok {
		return &ErrInvalidPacket{Err: errNotNFQueuePacket}
	}
	switch v {
	case VerdictAccept:
		return n.n.SetVerdict(nP.id, nfqueue.NfAccept)
	case VerdictAcceptModify:
		return n.n.SetVerdictModPacket(nP.id, nfqueue.NfAccept, newPacket)
	case VerdictAcceptStream:
		return n.n.SetVerdictWithConnMark(nP.id, nfqueue.NfAccept, n.connMarkAccept)
	case VerdictDrop:
		return n.n.SetVerdict(nP.id, nfqueue.NfDrop)
	case VerdictDropStream:
		return n.n.SetVerdictWithConnMark(nP.id, nfqueue.NfDrop, n.connMarkDrop)
	default:
		// Invalid verdict, ignore for now
		return nil
	}
}

func (n *nfqueuePacketIO) ProtectedDialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return n.protectedDialer.DialContext(ctx, network, address)
}

func (n *nfqueuePacketIO) Close() error {
	if n.rSet {
		if n.ipt4 != nil {
			_ = n.setupIpt(true)
		} else {
			_ = n.setupNft(true)
		}
		n.rSet = false
	}
	return n.n.Close()
}

// nfqueue IO does not issue shutdown
func (n *nfqueuePacketIO) SetCancelFunc(cancelFunc context.CancelFunc) error {
	return nil
}

func (n *nfqueuePacketIO) setupNft(remove bool) error {
	rules, err := n.generateNftRules()
	if err != nil {
		return err
	}
	rulesText := rules.String()
	if remove {
		err = nftDelete(nftFamily, n.table)
	} else {
		// Delete first to make sure no leftover rules
		_ = nftDelete(nftFamily, n.table)
		err = nftAdd(rulesText)
	}
	if err != nil {
		return err
	}
	return nil
}

func (n *nfqueuePacketIO) setupIpt(remove bool) error {
	rules, err := n.generateIptRules()
	if err != nil {
		return err
	}
	if remove {
		err = iptsBatchDeleteIfExists([]*iptables.IPTables{n.ipt4, n.ipt6}, rules)
	} else {
		err = iptsBatchAppendUnique([]*iptables.IPTables{n.ipt4, n.ipt6}, rules)
	}
	if err != nil {
		return err
	}
	return nil
}

var _ Packet = (*nfqueuePacket)(nil)

type nfqueuePacket struct {
	id        uint32
	streamID  uint32
	timestamp time.Time
	data      []byte
}

func (p *nfqueuePacket) StreamID() uint32 {
	return p.streamID
}

func (p *nfqueuePacket) Timestamp() time.Time {
	return p.timestamp
}

func (p *nfqueuePacket) Data() []byte {
	return p.data
}

func okBoolToInt(ok bool) int {
	if ok {
		return 0
	} else {
		return 1
	}
}

func nftCheck() error {
	_, err := exec.LookPath("nft")
	if err != nil {
		return err
	}
	return nil
}

func nftAdd(input string) error {
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(input)
	return cmd.Run()
}

func nftDelete(family, table string) error {
	cmd := exec.Command("nft", "delete", "table", family, table)
	return cmd.Run()
}

type nftTableSpec struct {
	Defines       []string
	Family, Table string
	Chains        []nftChainSpec
}

func (t *nftTableSpec) String() string {
	chains := make([]string, 0, len(t.Chains))
	for _, c := range t.Chains {
		chains = append(chains, c.String())
	}

	return fmt.Sprintf(`
%s

table %s %s {
%s
}
`, strings.Join(t.Defines, "\n"), t.Family, t.Table, strings.Join(chains, ""))
}

type nftChainSpec struct {
	Chain  string
	Header string
	Rules  []string
}

func (c *nftChainSpec) String() string {
	return fmt.Sprintf(`
  chain %s {
    %s
    %s
  }
`, c.Chain, c.Header, strings.Join(c.Rules, "\n\x20\x20\x20\x20"))
}

type iptRule struct {
	Table, Chain string
	RuleSpec     []string
}

func iptsBatchAppendUnique(ipts []*iptables.IPTables, rules []iptRule) error {
	for _, r := range rules {
		for _, ipt := range ipts {
			err := ipt.AppendUnique(r.Table, r.Chain, r.RuleSpec...)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func iptsBatchDeleteIfExists(ipts []*iptables.IPTables, rules []iptRule) error {
	for _, r := range rules {
		for _, ipt := range ipts {
			err := ipt.DeleteIfExists(r.Table, r.Chain, r.RuleSpec...)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func ctIDFromCtBytes(ct []byte) uint32 {
	ctAttrs, err := netlink.UnmarshalAttributes(ct)
	if err != nil {
		return 0
	}
	for _, attr := range ctAttrs {
		if attr.Type == 12 { // CTA_ID
			return binary.BigEndian.Uint32(attr.Data)
		}
	}
	return 0
}
