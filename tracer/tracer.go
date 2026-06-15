package tracer

import (
	"fmt"
	"net"
	"sync"
	"time"

	"gotrace/config"
	"gotrace/probe"
)

type TracerouteResult struct {
	TargetIP    net.IP
	TargetHost  string
	Hops        []*probe.HopResult
	Reachable   bool
	TotalTime   time.Duration
	StartTime   time.Time
	EndTime     time.Time
	LastHop     int
	AllStarFrom int
}

type Tracer struct {
	cfg    *config.Config
	prober probe.Prober
}

func NewTracer(cfg *config.Config, prober probe.Prober) *Tracer {
	return &Tracer{
		cfg:    cfg,
		prober: prober,
	}
}

func (t *Tracer) Run(target net.IP) (*TracerouteResult, error) {
	result := &TracerouteResult{
		TargetIP:    target,
		TargetHost:  target.String(),
		Hops:        make([]*probe.HopResult, 0, t.cfg.MaxHops),
		StartTime:   time.Now(),
		AllStarFrom: -1,
	}

	reached := false

	for hopNum := 1; hopNum <= t.cfg.MaxHops && !reached; hopNum++ {
		hopResult, err := t.probeSingleHop(hopNum, target)
		if err != nil {
			return result, fmt.Errorf("hop %d: %w", hopNum, err)
		}

		result.Hops = append(result.Hops, hopResult)
		result.LastHop = hopNum

		if hopResult.Reached {
			reached = true
			result.Reachable = true
		}

		if hopResult.Lost && result.AllStarFrom == -1 {
			result.AllStarFrom = hopNum
		} else if !hopResult.Lost {
			result.AllStarFrom = -1
		}
	}

	result.EndTime = time.Now()
	result.TotalTime = result.EndTime.Sub(result.StartTime)

	return result, nil
}

func (t *Tracer) probeSingleHop(hopNum int, target net.IP) (*probe.HopResult, error) {
	results := make([]*probe.ProbeResult, t.cfg.ProbesPerHop)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for i := 0; i < t.cfg.ProbesPerHop; i++ {
		wg.Add(1)
		go func(probeIdx int) {
			defer wg.Done()
			r, err := t.prober.ProbeHop(hopNum, probeIdx, target)
			if err != nil {
				r = &probe.ProbeResult{
					HopNum:   hopNum,
					ProbeIdx: probeIdx,
					RTTs:     []time.Duration{-1},
					TimedOut: true,
				}
			}
			mu.Lock()
			results[probeIdx] = r
			mu.Unlock()
		}(i)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(t.cfg.Timeout + time.Second):
	}

	ordered := make([]*probe.ProbeResult, t.cfg.ProbesPerHop)
	for i, r := range results {
		if r != nil {
			ordered[r.ProbeIdx] = r
		} else {
			ordered[i] = &probe.ProbeResult{
				HopNum:   hopNum,
				ProbeIdx: i,
				RTTs:     []time.Duration{-1},
				TimedOut: true,
			}
		}
	}

	return probe.AggregateHopResults(hopNum, ordered), nil
}

func (t *Tracer) Close() error {
	if t.prober != nil {
		return t.prober.Close()
	}
	return nil
}
