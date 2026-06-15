package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"gotrace/config"
	"gotrace/dnsutil"
	"gotrace/output"
	"gotrace/privilege"
	"gotrace/probe"
	"gotrace/tracer"
)

func main() {
	cfg, err := config.Parse()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	privResult := privilege.CheckAndAdjustMode(cfg)

	dnsResult, err := dnsutil.ResolveTarget(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "DNS resolution failed: %v\n", err)
		os.Exit(1)
	}

	ipStrs := make([]string, len(dnsResult.IPs))
	for i, ip := range dnsResult.IPs {
		ipStrs[i] = ip.String()
	}

	formatter := output.NewFormatter(cfg)
	formatter.PrintHeader(cfg.Target, ipStrs, dnsResult.ServerUsed, privResult)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	var tracerInst *tracer.Tracer
	var result *tracer.TracerouteResult

	for _, targetIP := range dnsResult.IPs {
		if len(dnsResult.IPs) > 1 {
			fmt.Printf("\n--- Tracing to %s ---\n", targetIP)
		}

		prober, err := probe.NewProber(cfg, targetIP, cfg.StartPort)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to create prober: %v\n", err)
			continue
		}

		tracerInst = tracer.NewTracer(cfg, prober)

		traceDone := make(chan struct{})
		go func() {
			result, err = tracerInst.Run(targetIP)
			close(traceDone)
		}()

		interrupted := false
		select {
		case <-sigCh:
			interrupted = true
			fmt.Println("\nInterrupted, stopping trace...")
		case <-traceDone:
		}

		tracerInst.Close()

		if interrupted {
			break
		}

		if err != nil {
			fmt.Fprintf(os.Stderr, "Trace error: %v\n", err)
			continue
		}

		for _, hop := range result.Hops {
			formatter.PrintHop(hop)
		}

		stats := formatter.ComputeStats(result)
		formatter.PrintSummary(result, stats)

		if !dnsResult.IsIPv6 && cfg.IPv6Only {
			break
		}
	}

	if result == nil {
		fmt.Fprintln(os.Stderr, "No valid traces completed")
		os.Exit(1)
	}
}
