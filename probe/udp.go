package probe

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"runtime"
	"syscall"
	"time"

	"gotrace/config"
)

type UDPProber struct {
	cfg        *config.Config
	target     net.IP
	startPort  int
	isIPv6     bool
	icmpConn   net.PacketConn
	udpConn    net.PacketConn
}

const (
	icmpv4Proto = 1
	icmpv6Proto = 58

	icmpTimeExceeded   = 11
	icmpDestUnreach    = 3
	icmpEchoReply      = 0
	icmpEchoRequest    = 8

	icmpv6TimeExceeded = 3
	icmpv6DestUnreach  = 1
	icmpv6EchoReply    = 129
	icmpv6EchoRequest  = 128
)

func NewUDPProber(cfg *config.Config, target net.IP, startPort int, isIPv6 bool) (*UDPProber, error) {
	p := &UDPProber{
		cfg:       cfg,
		target:    target,
		startPort: startPort,
		isIPv6:    isIPv6,
	}

	var err error

	network := "udp4"
	icmpNetwork := "ip4:icmp"
	if isIPv6 {
		network = "udp6"
		icmpNetwork = "ip6:ipv6-icmp"
	}

	p.udpConn, err = net.ListenPacket(network, ":0")
	if err != nil {
		return nil, fmt.Errorf("failed to create UDP socket: %w", err)
	}

	p.icmpConn, err = net.ListenPacket(icmpNetwork, "")
	if err != nil {
		p.udpConn.Close()
		return nil, fmt.Errorf("failed to create ICMP listener (may need root/CAP_NET_RAW on some systems): %w", err)
	}

	return p, nil
}

func (p *UDPProber) Close() error {
	var err1, err2 error
	if p.udpConn != nil {
		err1 = p.udpConn.Close()
	}
	if p.icmpConn != nil {
		err2 = p.icmpConn.Close()
	}
	if err1 != nil {
		return err1
	}
	return err2
}

func setUDPTTL(conn net.PacketConn, ttl int, isIPv6 bool) error {
	rawConn, err := conn.(*net.UDPConn).SyscallConn()
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

func (p *UDPProber) ProbeHop(hop int, probeIdx int, target net.IP) (*ProbeResult, error) {
	result := &ProbeResult{
		HopNum:   hop,
		ProbeIdx: probeIdx,
		RTTs:     []time.Duration{-1},
		TimedOut: true,
	}

	ctx, cancel := context.WithTimeout(context.Background(), p.cfg.Timeout)
	defer cancel()

	port := p.startPort + (hop-1)*p.cfg.ProbesPerHop + probeIdx

	dstAddr := &net.UDPAddr{IP: target, Port: port}

	payload := []byte("gotrace-probe")

	err := setUDPTTL(p.udpConn, hop, p.isIPv6)
	if err != nil {
		return result, fmt.Errorf("failed to set TTL: %w", err)
	}

	sendTime := time.Now()

	_, err = p.udpConn.WriteTo(payload, dstAddr)
	if err != nil {
		return result, fmt.Errorf("failed to send UDP: %w", err)
	}

	icmpCh := make(chan *icmpResponse, 1)
	errCh := make(chan error, 1)

	go p.waitForICMP(ctx, port, target, icmpCh, errCh)

	select {
	case resp := <-icmpCh:
		rtt := time.Since(sendTime)
		result.RTTs[0] = rtt
		result.TimedOut = false
		result.IP = resp.fromIP

		if p.isIPv6 {
			if resp.icmpType == icmpv6DestUnreach {
				result.Reached = true
			}
		} else {
			if resp.icmpType == icmpDestUnreach {
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

type icmpResponse struct {
	fromIP   net.IP
	icmpType uint8
	icmpCode uint8
	srcPort  uint16
	dstPort  uint16
}

func (p *UDPProber) waitForICMP(ctx context.Context, targetPort int, target net.IP, resultCh chan<- *icmpResponse, errCh chan<- error) {
	buf := make([]byte, 1500)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		p.icmpConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))

		n, srcAddr, err := p.icmpConn.ReadFrom(buf)
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

		resp := parseICMPResponse(buf[:n], p.isIPv6)
		if resp == nil {
			continue
		}

		var fromIP net.IP
		if udpAddr, ok := srcAddr.(*net.IPAddr); ok {
			fromIP = udpAddr.IP
		} else {
			continue
		}
		resp.fromIP = fromIP

		isTimeExceeded := false
		isDestUnreach := false

		if p.isIPv6 {
			isTimeExceeded = resp.icmpType == icmpv6TimeExceeded
			isDestUnreach = resp.icmpType == icmpv6DestUnreach
		} else {
			isTimeExceeded = resp.icmpType == icmpTimeExceeded
			isDestUnreach = resp.icmpType == icmpDestUnreach
		}

		if !isTimeExceeded && !isDestUnreach {
			continue
		}

		if isDestUnreach {
			if resp.dstPort == uint16(targetPort) || target.Equal(fromIP) {
				resp.fromIP = fromIP
				select {
				case resultCh <- resp:
				default:
				}
				return
			}
		}

		if isTimeExceeded {
			if resp.dstPort == uint16(targetPort) {
				select {
				case resultCh <- resp:
				default:
				}
				return
			}
		}
	}
}

func parseICMPResponse(data []byte, isIPv6 bool) *icmpResponse {
	if len(data) < 8 {
		return nil
	}

	resp := &icmpResponse{
		icmpType: data[0],
		icmpCode: data[1],
	}

	headerLen := 8

	var innerOffset int
	if isIPv6 {
		innerOffset = headerLen + 8
	} else {
		if len(data) > 20 {
			ihl := int(data[0]&0x0F) * 4
			innerOffset = headerLen + ihl
		} else {
			innerOffset = headerLen + 20
		}
	}

	if len(data) >= innerOffset+4 {
		inner := data[innerOffset:]
		if len(inner) >= 4 {
			resp.srcPort = binary.BigEndian.Uint16(inner[0:2])
			resp.dstPort = binary.BigEndian.Uint16(inner[2:4])
		}
	}

	return resp
}

func init() {
	runtime.GOMAXPROCS(runtime.NumCPU())
}
