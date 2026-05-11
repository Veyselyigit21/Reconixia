package cloudsafe

import (
	"fmt"
	"strings"
	"time"
)

type Provider string

const (
	DigitalOcean Provider = "digitalocean"
	Hetzner      Provider = "hetzner"
)

type Worker struct {
	Provider  Provider `json:"provider"`
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	IP        string   `json:"ip"`
	CreatedAt string   `json:"created_at"`
}

type FirewallPlan struct {
	Provider       Provider `json:"provider"`
	WorkerID       string   `json:"worker_id"`
	AllowSSH       bool     `json:"allow_ssh"`
	SSHCIDR        string   `json:"ssh_cidr"`
	DenyAllInbound bool     `json:"deny_all_inbound"`
}

func NormalizeProvider(raw string) (Provider, error) {
	s := strings.ToLower(strings.TrimSpace(raw))
	switch s {
	case "do", "digitalocean":
		return DigitalOcean, nil
	case "hcloud", "hetzner":
		return Hetzner, nil
	default:
		return "", fmt.Errorf("unsupported cloud provider: %s", raw)
	}
}

func NewWorker(provider Provider, id, name, ip string) Worker {
	return Worker{
		Provider:  provider,
		ID:        id,
		Name:      name,
		IP:        ip,
		CreatedAt: time.Now().Format(time.RFC3339),
	}
}

// NewFirewallPlan creates a firewall plan for a cloud worker.
// FIX: sshCIDR artık zorunlu — boş bırakılırsa hata döner.
// Eski davranış: boş CIDR = 0.0.0.0/0 (SSH herkese açık). Bu güvensiz.
func NewFirewallPlan(provider Provider, workerID, sshCIDR string) (FirewallPlan, error) {
	sshCIDR = strings.TrimSpace(sshCIDR)
	if sshCIDR == "" {
		return FirewallPlan{}, fmt.Errorf(
			"sshCIDR boş bırakılamaz: kendi IP adresinizi girin (örn: 1.2.3.4/32). " +
				"'curl -s ifconfig.me' komutuyla öğrenebilirsiniz",
		)
	}
	// Basit CIDR format kontrolü
	if !strings.Contains(sshCIDR, "/") {
		return FirewallPlan{}, fmt.Errorf("geçersiz CIDR formatı: %q — örnek: 1.2.3.4/32", sshCIDR)
	}
	return FirewallPlan{
		Provider:       provider,
		WorkerID:       workerID,
		AllowSSH:       true,
		SSHCIDR:        sshCIDR,
		DenyAllInbound: true,
	}, nil
}

func CleanupRequired(w Worker) bool {
	return strings.TrimSpace(w.ID) != "" && w.Provider != ""
}
