package dnsutil

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"time"

	"gotrace/config"
)

type ResolveResult struct {
	IPs        []net.IP
	ServerUsed string
	Latency    time.Duration
	IsIPv6     bool
}

func ResolveTarget(cfg *config.Config) (*ResolveResult, error) {
	ip := net.ParseIP(cfg.Target)
	if ip != nil {
		isIPv6 := ip.To4() == nil
		if cfg.IPv4Only && isIPv6 {
			return nil, fmt.Errorf("target %q is IPv6 but --ipv4-only specified", cfg.Target)
		}
		if cfg.PreferIPv6 && !isIPv6 {
			return nil, fmt.Errorf("target %q is IPv4 but --ipv6 specified", cfg.Target)
		}
		return &ResolveResult{
			IPs:        []net.IP{ip},
			ServerUsed: "literal",
			Latency:    0,
			IsIPv6:     isIPv6,
		}, nil
	}

	var wantIPv4, wantIPv6 bool
	if cfg.IPv4Only {
		wantIPv4 = true
	} else if cfg.PreferIPv6 {
		wantIPv6 = true
	} else {
		wantIPv4 = true
		wantIPv6 = true
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	type serverResult struct {
		result *ResolveResult
		err    error
	}

	results := make(chan serverResult, len(cfg.DNSServers))
	var wg sync.WaitGroup

	for _, server := range cfg.DNSServers {
		wg.Add(1)
		go func(dnsServer string) {
			defer wg.Done()
			start := time.Now()

			r := &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
					d := net.Dialer{Timeout: 2 * time.Second}
					return d.DialContext(ctx, "udp", dnsServer)
				},
			}

			var ips []net.IP
			var err error

			if wantIPv4 {
				addrs, err4 := r.LookupIP(ctx, "ip4", cfg.Target)
				if err4 == nil {
					ips = append(ips, addrs...)
				}
				err = err4
			}

			if wantIPv6 {
				addrs, err6 := r.LookupIP(ctx, "ip6", cfg.Target)
				if err6 == nil {
					ips = append(ips, addrs...)
				}
				if err == nil {
					err = err6
				}
			}

			latency := time.Since(start)

			if len(ips) > 0 {
				isIPv6 := len(ips) > 0 && ips[0].To4() == nil
				results <- serverResult{
					result: &ResolveResult{
						IPs:        ips,
						ServerUsed: dnsServer,
						Latency:    latency,
						IsIPv6:     isIPv6,
					},
					err: nil,
				}
			} else {
				results <- serverResult{result: nil, err: fmt.Errorf("dns %s: %w", dnsServer, err)}
			}
		}(server)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	var best *ResolveResult
	var errors []error

	for res := range results {
		if res.err != nil {
			errors = append(errors, res.err)
			continue
		}
		if best == nil || res.result.Latency < best.Latency {
			best = res.result
		}
	}

	if best == nil {
		sysIPs, sysErr := net.LookupIP(cfg.Target)
		if sysErr == nil && len(sysIPs) > 0 {
			filtered := filterIPs(sysIPs, wantIPv4, wantIPv6)
			if len(filtered) > 0 {
				isIPv6 := filtered[0].To4() == nil
				best = &ResolveResult{
					IPs:        filtered,
					ServerUsed: "system",
					Latency:    0,
					IsIPv6:     isIPv6,
				}
			}
		}
	}

	if best == nil {
		return nil, fmt.Errorf("failed to resolve %q: %v", cfg.Target, errors)
	}

	best.IPs = selectIPs(best.IPs, cfg.IPSelection)
	return best, nil
}

func filterIPs(ips []net.IP, wantIPv4, wantIPv6 bool) []net.IP {
	var result []net.IP
	for _, ip := range ips {
		isIPv4 := ip.To4() != nil
		if isIPv4 && wantIPv4 {
			result = append(result, ip)
		} else if !isIPv4 && wantIPv6 {
			result = append(result, ip)
		}
	}
	return result
}

func selectIPs(ips []net.IP, selection config.IPSelection) []net.IP {
	if len(ips) == 0 {
		return ips
	}

	switch selection {
	case config.IPFirst:
		return []net.IP{ips[0]}
	case config.IPRandom:
		idx := rand.Intn(len(ips))
		return []net.IP{ips[idx]}
	case config.IPAll:
		return ips
	default:
		return []net.IP{ips[0]}
	}
}

func ReverseLookup(ip net.IP) string {
	names, err := net.LookupAddr(ip.String())
	if err != nil || len(names) == 0 {
		return ip.String()
	}
	for i := range names {
		if len(names[i]) > 0 && names[i][len(names[i])-1] == '.' {
			names[i] = names[i][:len(names[i])-1]
		}
	}
	return names[0]
}
