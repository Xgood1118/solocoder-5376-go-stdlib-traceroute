package privilege

import (
	"os"
	"runtime"

	"gotrace/config"
)

type CheckResult struct {
	IsAdmin       bool
	CanUseICMP    bool
	Downgraded    bool
	OriginalMode  config.ProbeMode
	EffectiveMode config.ProbeMode
	Warnings      []string
}

func CheckAndAdjustMode(cfg *config.Config) *CheckResult {
	result := &CheckResult{
		OriginalMode:  cfg.Mode,
		EffectiveMode: cfg.Mode,
	}

	result.IsAdmin = isAdmin()
	result.CanUseICMP = canUseICMPRaw()

	if cfg.Mode == config.ModeICMP && !result.CanUseICMP {
		result.Downgraded = true
		result.EffectiveMode = config.ModeUDP
		cfg.Mode = config.ModeUDP
		result.Warnings = append(result.Warnings,
			"warning: need root/CAP_NET_RAW for ICMP mode, falling back to UDP (try --udp instead)")
	}

	if !result.CanUseICMP {
		result.Warnings = append(result.Warnings,
			"info: hops shown as * * * may be NAT devices blocking ICMP or router misconfiguration")
	}

	return result
}

func isAdmin() bool {
	switch runtime.GOOS {
	case "linux", "darwin", "freebsd", "netbsd", "openbsd", "dragonfly":
		return os.Getuid() == 0
	case "windows":
		return isWindowsAdmin()
	default:
		return false
	}
}
