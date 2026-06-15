package config

import (
	"flag"
	"fmt"
	"os"
	"time"
)

type ProbeMode string

const (
	ModeUDP  ProbeMode = "udp"
	ModeICMP ProbeMode = "icmp"
)

type IPSelection string

const (
	IPFirst   IPSelection = "first"
	IPRandom  IPSelection = "random"
	IPAll     IPSelection = "all"
)

type Config struct {
	Target       string
	Mode         ProbeMode
	MaxHops      int
	Timeout      time.Duration
	StartPort    int
	IPv4Only     bool
	IPv6Only     bool
	PreferIPv6   bool
	IPSelection  IPSelection
	DNSServers   []string
	ProbesPerHop int
	ShowHelp     bool
}

var defaultDNSServers = []string{
	"8.8.8.8:53",
	"1.1.1.1:53",
	"114.114.114.114:53",
}

func Parse() (*Config, error) {
	cfg := &Config{}

	var (
		modeStr      string
		icmpFlag     bool
		udpFlag      bool
		ipSelectStr  string
		dnsServers   string
		timeoutStr   string
	)

	flag.StringVar(&modeStr, "mode", "udp", "probe mode: udp or icmp")
	flag.BoolVar(&udpFlag, "udp", false, "use UDP mode (default)")
	flag.BoolVar(&icmpFlag, "icmp", false, "use ICMP mode (need root/CAP_NET_RAW)")
	flag.IntVar(&cfg.MaxHops, "max-hops", 30, "maximum number of hops")
	flag.IntVar(&cfg.MaxHops, "m", 30, "maximum number of hops (shorthand)")
	flag.StringVar(&timeoutStr, "timeout", "3s", "timeout per probe (e.g. 2s, 500ms)")
	flag.StringVar(&timeoutStr, "t", "3s", "timeout per probe (shorthand)")
	flag.IntVar(&cfg.StartPort, "port", 33434, "UDP starting port")
	flag.IntVar(&cfg.StartPort, "p", 33434, "UDP starting port (shorthand)")
	flag.BoolVar(&cfg.IPv4Only, "ipv4-only", false, "resolve IPv4 only (A records)")
	flag.BoolVar(&cfg.IPv4Only, "4", false, "resolve IPv4 only (shorthand)")
	flag.BoolVar(&cfg.PreferIPv6, "ipv6", false, "prefer IPv6 (AAAA records)")
	flag.BoolVar(&cfg.PreferIPv6, "6", false, "prefer IPv6 (shorthand)")
	flag.StringVar(&ipSelectStr, "select", "first", "IP selection: first, random, or all")
	flag.IntVar(&cfg.ProbesPerHop, "probes", 3, "number of probes per hop")
	flag.StringVar(&dnsServers, "dns", "", "comma-separated DNS servers (e.g. 8.8.8.8:53,1.1.1.1:53)")
	flag.BoolVar(&cfg.ShowHelp, "help", false, "show help message")
	flag.BoolVar(&cfg.ShowHelp, "h", false, "show help message (shorthand)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] <target>\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "A simplified traceroute implementation in Go.\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s baidu.com\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s --icmp --max-hops 20 google.com\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s --timeout 2s --port 33450 example.com\n", os.Args[0])
	}

	flag.Parse()

	if cfg.ShowHelp {
		flag.Usage()
		os.Exit(0)
	}

	if flag.NArg() < 1 {
		flag.Usage()
		return nil, fmt.Errorf("target is required")
	}

	cfg.Target = flag.Arg(0)

	modeFlagPassed := isFlagPassed("mode")

	if icmpFlag {
		cfg.Mode = ModeICMP
	} else if modeFlagPassed && modeStr == "icmp" {
		cfg.Mode = ModeICMP
	} else if udpFlag || (modeFlagPassed && modeStr == "udp") {
		cfg.Mode = ModeUDP
	} else {
		cfg.Mode = ModeUDP
	}

	if cfg.ProbesPerHop < 1 {
		cfg.ProbesPerHop = 1
	}
	if cfg.ProbesPerHop > 10 {
		cfg.ProbesPerHop = 10
	}

	d, err := time.ParseDuration(timeoutStr)
	if err != nil {
		return nil, fmt.Errorf("invalid timeout %q: %w", timeoutStr, err)
	}
	cfg.Timeout = d

	switch ipSelectStr {
	case "first", "random", "all":
		cfg.IPSelection = IPSelection(ipSelectStr)
	default:
		return nil, fmt.Errorf("invalid IP selection %q (use first, random, or all)", ipSelectStr)
	}

	if dnsServers != "" {
		var servers []string
		for _, s := range splitAndTrim(dnsServers, ",") {
			if s != "" {
				servers = append(servers, normalizeDNSServer(s))
			}
		}
		cfg.DNSServers = append(defaultDNSServers, servers...)
	} else {
		cfg.DNSServers = defaultDNSServers
	}

	cfg.IPv6Only = cfg.PreferIPv6 && cfg.IPv4Only == false

	return cfg, nil
}

func isFlagPassed(name string) bool {
	found := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

func splitAndTrim(s, sep string) []string {
	var result []string
	for _, part := range splitString(s, sep) {
		trimmed := trimSpaces(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func splitString(s, sep string) []string {
	var result []string
	start := 0
	for i := 0; i <= len(s)-len(sep); i++ {
		if s[i:i+len(sep)] == sep {
			result = append(result, s[start:i])
			start = i + len(sep)
			i += len(sep) - 1
		}
	}
	result = append(result, s[start:])
	return result
}

func trimSpaces(s string) string {
	start := 0
	end := len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}

func normalizeDNSServer(s string) string {
	hasPort := false
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == ':' {
			hasPort = true
			break
		}
	}
	if !hasPort {
		return s + ":53"
	}
	return s
}
