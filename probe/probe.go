package probe

import (
	"net"
	"time"

	"gotrace/config"
)

type ProbeResult struct {
	HopNum    int
	RTTs      []time.Duration
	IP        net.IP
	Hostname  string
	Reached   bool
	TimedOut  bool
	ProbeIdx  int
}

type HopResult struct {
	HopNum   int
	RTTs     []time.Duration
	IP       net.IP
	Hostname string
	Reached  bool
	Lost     bool
}

type Prober interface {
	ProbeHop(hop int, probeIdx int, target net.IP) (*ProbeResult, error)
	Close() error
}

func NewProber(cfg *config.Config, target net.IP, startPort int) (Prober, error) {
	isIPv6 := target.To4() == nil
	switch cfg.Mode {
	case config.ModeICMP:
		return NewICMPProber(cfg, isIPv6)
	case config.ModeUDP:
		fallthrough
	default:
		return NewUDPProber(cfg, target, startPort, isIPv6)
	}
}

func AggregateHopResults(hopNum int, results []*ProbeResult) *HopResult {
	hop := &HopResult{
		HopNum: hopNum,
		RTTs:   make([]time.Duration, len(results)),
	}

	allTimedOut := true
	anyReached := false

	for i, r := range results {
		if r == nil {
			hop.RTTs[i] = -1
			continue
		}
		hop.RTTs[i] = r.RTTs[0]
		if !r.TimedOut {
			allTimedOut = false
			if hop.IP == nil && r.IP != nil {
				hop.IP = r.IP
			}
		}
		if r.Reached {
			anyReached = true
		}
	}

	hop.Lost = allTimedOut
	hop.Reached = anyReached

	if hop.IP != nil {
		hop.Hostname = hop.IP.String()
	}

	return hop
}
