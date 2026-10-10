// Package subenum collects passive subdomains from sources beyond subfinder.
// All sources are passive (public CT logs, public passive-DNS style tools) and
// every result is re-validated through the safety/scope layer before use.
package subenum

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/Veyselyigit21/Reconixia/internal/safety"
)

// Result holds the merged passive subdomain set plus per-source counts and
// any non-fatal warnings produced while gathering it.
type Result struct {
	Hosts    []string
	Sources  map[string]int
	Warnings []string
}

// Passive queries crt.sh and (if installed) assetfinder, then returns the
// in-scope, deduplicated hostname set. Failures in any single source are
// recorded as warnings and never abort the run.
func Passive(ctx context.Context, target string, rules []string, timeout time.Duration) Result {
	res := Result{Sources: map[string]int{}}
	seen := map[string]bool{}

	add := func(source string, hosts []string) {
		n := 0
		for _, h := range hosts {
			host, ok := safety.NormalizeTarget(h)
			if !ok || seen[host] {
				continue
			}
			if !safety.ScopeAllowsURL("https://"+host, rules) {
				continue
			}
			seen[host] = true
			res.Hosts = append(res.Hosts, host)
			n++
		}
		if n > 0 {
			res.Sources[source] += n
		}
	}

	crt, err := crtSh(ctx, target, timeout)
	if err != nil {
		res.Warnings = append(res.Warnings, "crt.sh pasif kaynak atlandı: "+err.Error())
	} else {
		add("crt.sh", crt)
	}

	af, err := assetfinder(ctx, target, timeout)
	if err != nil {
		res.Warnings = append(res.Warnings, err.Error())
	} else {
		add("assetfinder", af)
	}

	sort.Strings(res.Hosts)
	return res
}

type crtEntry struct {
	NameValue  string `json:"name_value"`
	CommonName string `json:"common_name"`
}

// crtSh pulls certificate-transparency names for the target from crt.sh. The
// request goes through the SSRF-safe client, so crt.sh must resolve to a public
// IP like any other fetch.
func crtSh(ctx context.Context, target string, timeout time.Duration) ([]string, error) {
	if timeout <= 0 {
		timeout = 25 * time.Second
	}
	client := safety.SafeHTTPClient(timeout)
	url := "https://crt.sh/?q=%25." + target + "&output=json"
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Reconixia/1.0 AuthorizedResearch")
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crt.sh HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16_000_000))
	if err != nil {
		return nil, err
	}
	var entries []crtEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("crt.sh JSON çözülemedi: %w", err)
	}
	out := []string{}
	for _, e := range entries {
		for _, field := range []string{e.NameValue, e.CommonName} {
			for _, name := range strings.Split(field, "\n") {
				name = strings.TrimSpace(strings.ToLower(name))
				name = strings.TrimPrefix(name, "*.")
				if name != "" {
					out = append(out, name)
				}
			}
		}
	}
	return out, nil
}

// assetfinder runs the assetfinder binary when present. Missing binary is a
// soft skip, not an error the caller should surface loudly.
func assetfinder(ctx context.Context, target string, timeout time.Duration) ([]string, error) {
	if _, err := exec.LookPath("assetfinder"); err != nil {
		return nil, fmt.Errorf("assetfinder yok; ek pasif kaynak atlandı (opsiyonel)")
	}
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(runCtx, "assetfinder", "--subs-only", target)
	out, err := cmd.Output()
	if runCtx.Err() == context.DeadlineExceeded {
		return nil, fmt.Errorf("assetfinder timeout (%s); atlandı", timeout)
	}
	if err != nil {
		return nil, fmt.Errorf("assetfinder çalıştırılamadı: %v", err)
	}
	return strings.Split(string(out), "\n"), nil
}
