package modules

type OptionalModules struct {
	PortScan       bool `json:"port_scan"`
	Screenshots    bool `json:"screenshots"`
	ParamDiscovery bool `json:"param_discovery"`
	Bypass403      bool `json:"bypass_403"`
}

type Limits struct {
	MaxHosts       int `json:"max_hosts"`
	MaxURLs        int `json:"max_urls"`
	RatePerSecond  int `json:"rate_per_second"`
	TimeoutSeconds int `json:"timeout_seconds"`
}

func Defaults(profile string) Limits {
	switch profile {
	case "fast":
		return Limits{MaxHosts: 500, MaxURLs: 2000, RatePerSecond: 20, TimeoutSeconds: 8}
	case "stealth":
		return Limits{MaxHosts: 100, MaxURLs: 500, RatePerSecond: 2, TimeoutSeconds: 10}
	default:
		return Limits{MaxHosts: 250, MaxURLs: 1000, RatePerSecond: 8, TimeoutSeconds: 10}
	}
}

func Clip[T any](in []T, max int) []T {
	if max <= 0 || len(in) <= max {
		return in
	}
	return in[:max]
}
