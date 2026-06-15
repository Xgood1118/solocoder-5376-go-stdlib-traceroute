package probe

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"time"

	"gotrace/config"
)

type ICMPProber struct {
	cfg     *config.Config
	isIPv6  bool
	conn    net.PacketConn
	nextSeq uint16
}

type icmpReply struct {
	from net.IP
	typ  uint8
	code uint8
	seq  uint16
	id   uint16
}

func NewICMPProber(cfg *config.Config, isIPv6 bool) (*ICMPProber, error) {
	p := &ICMPProber{
		cfg:    cfg,
		isIPv6: isIPv6,
	}

	var err error
	if isIPv6 {
		p.conn, err = net.ListenPacket("ip6:ipv6-icmp", "")
	} else {
		p.conn, err = net.ListenPacket("ip4:icmp", "")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create ICMP raw socket (need root/CAP_NET_RAW): %w", err)
	}

	return p, nil
}

func (p *ICMPProber) Close() error {
	if p.conn != nil {
		return p.conn.Close()
	}
	return nil
}

func icmpChecksum(data []byte) uint16 {
	var sum uint32
	n := len(data)
	i := 0
	for i+1 < n {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
		i += 2
	}
	if i < n {
		sum += uint32(data[i]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

func (p *ICMPProber) buildEchoRequest(id uint16, seq uint16) []byte {
	var msg []byte

	if p.isIPv6 {
		msg = make([]byte, 8+56)
		msg[0] = icmpv6EchoRequest
		msg[1] = 0
		binary.BigEndian.PutUint16(msg[4:6], id)
		binary.BigEndian.PutUint16(msg[6:8], seq)
		for i := 8; i < len(msg); i++ {
			msg[i] = byte(i - 8)
		}
		checksum := icmpChecksum(msg)
		binary.BigEndian.PutUint16(msg[2:4], checksum)
	} else {
		msg = make([]byte, 8+56)
		msg[0] = icmpEchoRequest
		msg[1] = 0
		binary.BigEndian.PutUint16(msg[4:6], id)
		binary.BigEndian.PutUint16(msg[6:8], seq)
		for i := 8; i < len(msg); i++ {
			msg[i] = byte(i - 8)
		}
		checksum := icmpChecksum(msg)
		binary.BigEndian.PutUint16(msg[2:4], checksum)
	}

	return msg
}

func setICMPTTL(conn net.PacketConn, ttl int, isIPv6 bool) error {
	rawConn, err := conn.(*net.IPConn).SyscallConn()
	if err != nil {
		return err
	}

	var setErr error
	err = rawConn.Control(func(fd uintptr) {
		if isIPv6 {
			setErr = setsockoptInt(fd, syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS, ttl)
		} else {
			setErr = setsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_TTL, ttl)
		}
	})
	if err != nil {
		return err
	}
	return setErr
}

func (p *ICMPProber) ProbeHop(hop int, probeIdx int, target net.IP) (*ProbeResult, error) {
	result := &ProbeResult{
		HopNum:   hop,
		ProbeIdx: probeIdx,
		RTTs:     []time.Duration{-1},
		TimedOut: true,
	}

	ctx, cancel := context.WithTimeout(context.Background(), p.cfg.Timeout)
	defer cancel()

	seq := p.nextSeq
	p.nextSeq++
	id := uint16(syscall.Getpid() & 0xFFFF)

	pkt := p.buildEchoRequest(id, seq)

	err := setICMPTTL(p.conn, hop, p.isIPv6)
	if err != nil {
		return result, fmt.Errorf("failed to set TTL: %w", err)
	}

	sendTime := time.Now()

	dstAddr := &net.IPAddr{IP: target}
	_, err = p.conn.WriteTo(pkt, dstAddr)
	if err != nil {
		return result, fmt.Errorf("failed to send ICMP: %w", err)
	}

	replyCh := make(chan *icmpReply, 1)
	errCh := make(chan error, 1)

	go p.waitForReply(ctx, id, seq, replyCh, errCh)

	select {
	case reply := <-replyCh:
		rtt := time.Since(sendTime)
		result.RTTs[0] = rtt
		result.TimedOut = false
		result.IP = reply.from

		if p.isIPv6 {
			if reply.typ == icmpv6EchoReply {
				result.Reached = true
			}
		} else {
			if reply.typ == icmpEchoReply {
				result.Reached = true
			}
		}

	case <-ctx.Done():
		result.TimedOut = true
	case <-errCh:
		result.TimedOut = true
	}

	return result, nil
}

func (p *ICMPProber) waitForReply(ctx context.Context, expectID, expectSeq uint16, replyCh chan<- *icmpReply, errCh chan<- error) {
	buf := make([]byte, 1500)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		p.conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))

		n, srcAddr, err := p.conn.ReadFrom(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			select {
			case errCh <- err:
			default:
			}
			return
		}

		if n < 8 {
			continue
		}

		var fromIP net.IP
		if ipAddr, ok := srcAddr.(*net.IPAddr); ok {
			fromIP = ipAddr.IP
		} else {
			continue
		}

		typ := buf[0]
		code := buf[1]

		var replyID, replySeq uint16
		var matched bool

		isTimeExceeded := false
		isEchoReply := false

		if p.isIPv6 {
			isTimeExceeded = typ == icmpv6TimeExceeded
			isEchoReply = typ == icmpv6EchoReply
		} else {
			isTimeExceeded = typ == icmpTimeExceeded
			isEchoReply = typ == icmpEchoReply
		}

		if isEchoReply {
			if n >= 8 {
				replyID = binary.BigEndian.Uint16(buf[4:6])
				replySeq = binary.BigEndian.Uint16(buf[6:8])
				if replyID == expectID && replySeq == expectSeq {
					matched = true
				}
			}
		} else if isTimeExceeded {
			var innerStart int
			if p.isIPv6 {
				innerStart = 8 + 40
			} else {
				innerStart = 8 + 20
			}
			if len(buf) >= innerStart+8 {
				innerICMP := buf[innerStart:]
				replyID = binary.BigEndian.Uint16(innerICMP[4:6])
				replySeq = binary.BigEndian.Uint16(innerICMP[6:8])
				if replyID == expectID && replySeq == expectSeq {
					matched = true
				}
			}
		}

		if matched {
			select {
			case replyCh <- &icmpReply{
				from: fromIP,
				typ:  typ,
				code: code,
				seq:  replySeq,
				id:   replyID,
			}:
			default:
			}
			return
		}
	}
}
