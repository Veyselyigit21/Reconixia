package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Veyselyigit21/Reconixia/internal/safety"
	"github.com/Veyselyigit21/Reconixia/internal/techrank"
)

// ── Tipler ──────────────────────────────────────────────────────────────────

var version = "0.9.0-rc1"

type Profile struct {
	Name       string        `json:"name"`
	Rate       int           `json:"rate_per_second"`
	Threads    int           `json:"threads"`
	Timeout    time.Duration `json:"-"`
	GAUTimeout time.Duration `json:"-"`
}

type Finding struct {
	Type       string `json:"type"`
	URL        string `json:"url"`
	Status     int    `json:"status"`
	Confidence string `json:"confidence"`
	Note       string `json:"note"`
}

type EndpointProbe struct {
	Endpoint        string           `json:"endpoint"`
	URL             string           `json:"url"`
	GETStatus       int              `json:"get_status"`
	HEADStatus      int              `json:"head_status,omitempty"`
	OPTIONSStatus   int              `json:"options_status,omitempty"`
	ContentType     string           `json:"content_type,omitempty"`
	Size            int64            `json:"size,omitempty"`
	Allow           string           `json:"allow,omitempty"`
	CORSAllowOrigin string           `json:"cors_allow_origin,omitempty"`
	Classification  string           `json:"classification"`
	Note            string           `json:"note"`
	SensitiveFields []SensitiveField `json:"sensitive_fields,omitempty"`
	RiskScore       int              `json:"risk_score,omitempty"`
	Risk            string           `json:"risk,omitempty"`
}

type SensitiveField struct {
	Path     string `json:"path"`
	Category string `json:"category"`
	Severity string `json:"severity"`
}

type Report struct {
	Target           string          `json:"target"`
	Profile          Profile         `json:"profile"`
	GeneratedAt      string          `json:"generated_at"`
	Subdomains       []string        `json:"subdomains"`
	LiveHosts        []string        `json:"live_hosts"`
	PassiveURLs      []string        `json:"passive_urls"`
	JSFiles          []string        `json:"js_files"`
	Endpoints        []string        `json:"endpoints"`
	EndpointProbes   []EndpointProbe `json:"endpoint_probes,omitempty"`
	Findings         []Finding       `json:"findings"`
	TechSummary      []techrank.Item `json:"tech_summary,omitempty"`
	DiscoveredParams []string        `json:"discovered_params,omitempty"`
	Warnings         []string        `json:"warnings"`
	ExportTarget     string          `json:"export_target"`
}

type Options struct {
	Target      string
	ScopeFile   string
	Profile     string
	SeedURL     string
	Wordlist    string
	NoNuclei    bool
	Severity    string
	NoGAU       bool
	NoHeaders   bool
	Resume      bool
	ResetResume bool
	LabMode     bool
	NoSubenum   bool
	NoBuckets   bool
	PruneDead   bool
	Katana      bool
	Arjun       bool
	XSS         bool
	DAST        bool
}

type limiter struct{ tick <-chan time.Time }

func newLimiter(rate int) *limiter {
	if rate < 1 {
		rate = 1
	}
	return &limiter{tick: time.Tick(time.Second / time.Duration(rate))}
}

func (l *limiter) wait() { <-l.tick }

// ── Entry point ──────────────────────────────────────────────────────────────

func main() {
	loadEnv()
	if len(os.Args) == 1 {
		menu()
		return
	}
	switch os.Args[1] {
	case "setup", "keys":
		setup()
	case "doctor":
		doctor()
	case "version", "--version", "-version":
		fmt.Println("Reconixia", version)
	case "run":
		cmdRun(os.Args[2:])
	case "analyze":
		cmdAnalyze(os.Args[2:])
	default:
		usage()
	}
}

func usage() {
	fmt.Println("Reconixia " + version)
	fmt.Println("  reconixia")
	fmt.Println("  reconixia setup")
	fmt.Println("  reconixia doctor")
	fmt.Println("  reconixia version")
	fmt.Println("  reconixia run -target hedef.com [-scope scope.txt] [-profile balanced] [-seed-url http://localhost:3000] [-h1-user username] [-resume] [-no-gau] [-no-headers] [-lab-mode]")
	fmt.Println("      [-no-subenum] [-no-buckets] [-prune-dead] [-katana] [-arjun] [-xss] [-dast]")
	fmt.Println("  reconixia analyze -target hedef.com [-provider local|openrouter|openai|deepseek] [-model model] [-lab-mode]")
}

func menu() {
	in := bufio.NewReader(os.Stdin)
	for {
		printMainMenu()
		switch ask(in, colorize("Select", ansiCyan), "") {
		case "1":
			t := ask(in, "Target domain", "")
			h1 := ask(in, "HackerOne username", getenv("RECONIXIA_H1_USERNAME", ""))
			if h1 != "" {
				_ = os.Setenv("RECONIXIA_H1_USERNAME", h1)
			}
			_, err := run(context.Background(), Options{
				Target:   t,
				Profile:  "stealth",
				Severity: "info,low",
				NoNuclei: true,
				Resume:   true,
			})
			if err != nil {
				fmt.Println(colorize("Error:", ansiRed), err)
			}
		case "2":
			t := ask(in, "Target domain", "")
			p := ask(in, "Profile [stealth/balanced/fast]", "balanced")
			s := ask(in, "Scope file", "")
			w := ask(in, "Wordlist", "")
			h1 := ask(in, "HackerOne username", getenv("RECONIXIA_H1_USERNAME", ""))
			if h1 != "" {
				_ = os.Setenv("RECONIXIA_H1_USERNAME", h1)
			}
			_, err := run(context.Background(), Options{
				Target:    t,
				Profile:   p,
				ScopeFile: s,
				Wordlist:  w,
				Severity:  "info,low,medium",
				NoNuclei:  true,
				Resume:    true,
			})
			if err != nil {
				fmt.Println(colorize("Error:", ansiRed), err)
			}
		case "3":
			t := ask(in, "Target", "")
			provider := ask(in, "Provider", getenv("RECONIXIA_AI_PROVIDER", "local"))
			model := ask(in, "Model", "")
			if err := analyze(t, provider, model); err != nil {
				fmt.Println(colorize("Error:", ansiRed), err)
			}
		case "4":
			printIDORGuide(in)
		case "5":
			setup()
		case "6":
			doctor()
		case "0":
			return
		default:
			fmt.Println(colorize("Invalid selection", ansiRed))
		}
	}
}

const (
	ansiReset = "\033[0m"
	ansiBold  = "\033[1m"
	ansiDim   = "\033[2m"
	ansiCyan  = "\033[38;5;51m"
	ansiBlue  = "\033[38;5;45m"
	ansiRed   = "\033[38;5;203m"
	ansiGreen = "\033[38;5;84m"
	ansiGold  = "\033[38;5;221m"
	ansiMuted = "\033[38;5;244m"
)

func colorize(s, style string) string {
	if os.Getenv("NO_COLOR") != "" {
		return s
	}
	return style + s + ansiReset
}

func printMainMenu() {
	fmt.Println()
	fmt.Println(colorize("  +---------------------------------------------------------------+", ansiMuted))
	fmt.Println(colorize("  |  </>                                           [ AI ]         |", ansiRed))
	fmt.Println(colorize("  |                                                               |", ansiMuted))
	fmt.Println(colorize("  |  RECONIXIA                                                    |", ansiBold+ansiCyan))
	fmt.Println(colorize("  |  AI bug bounty command console                                |", ansiRed))
	fmt.Println(colorize("  |                                                               |", ansiMuted))
	fmt.Println(colorize("  |  RECON  |  IDOR  |  OAST  |  AI  |  REPORT                    |", ansiBlue))
	fmt.Println(colorize("  +---------------------------------------------------------------+", ansiMuted))
	fmt.Println(colorize("  version "+version, ansiMuted))
	fmt.Println()
	menuItem("1", "Quick Recon", "stealth, resume, safe defaults")
	menuItem("2", "Bounty Recon", "scoped recon with endpoint triage")
	menuItem("3", "AI Analysis", "local/OpenRouter/OpenAI/DeepSeek")
	menuItem("4", "IDOR/BOLA Guide", "owned-account replay command helper")
	menuItem("5", "Setup", "API keys and defaults")
	menuItem("6", "Doctor", "toolchain and dependency check")
	menuItem("0", "Exit", "close console")
	fmt.Println()
}

func menuItem(key, title, desc string) {
	fmt.Printf("  %s  %s  %s\n",
		colorize("["+key+"]", ansiGold),
		colorize(title, ansiBold),
		colorize(desc, ansiDim))
}

func printIDORGuide(in *bufio.Reader) {
	target := ask(in, "Target domain", "")
	rules := ask(in, "Rules file", "examples/program-policies/whatnot.idor-policy.example.json")
	rate := ask(in, "Rate", "2")
	max := ask(in, "Max replay", "50")
	if !strings.HasSuffix(target, ".com") && !strings.Contains(target, ".") {
		fmt.Println(colorize("Tip:", ansiGold), "use the exact in-scope host, for example api.example.com")
	}
	fmt.Println()
	fmt.Println(colorize("Export two owned-account auth headers, then run:", ansiCyan))
	fmt.Println("export RECONIXIA_IDOR_AUTH_A='Authorization: Bearer ACCOUNT_A_TOKEN'")
	fmt.Println("export RECONIXIA_IDOR_AUTH_B='Authorization: Bearer ACCOUNT_B_TOKEN'")
	fmt.Println("./reconixia-idor \\")
	fmt.Printf("  -target %q \\\n", target)
	fmt.Println("  -har owned-account.har \\")
	fmt.Printf("  -rules %q \\\n", rules)
	fmt.Printf("  -rate %s \\\n", rate)
	fmt.Printf("  -max %s\n", max)
	fmt.Println()
	fmt.Println(colorize("Only replay requests from accounts you own and control.", ansiMuted))
}

// ── run komutu ───────────────────────────────────────────────────────────────

func cmdRun(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	target := fs.String("target", "", "hedef domain")
	scope := fs.String("scope", "", "scope dosyası")
	prof := fs.String("profile", "balanced", "stealth|balanced|fast")
	seedURL := fs.String("seed-url", "", "explicit base URL to scan, useful for local labs with custom ports")
	wordlist := fs.String("wordlist", "", "wordlist dosyası")
	noNuclei := fs.Bool("no-nuclei", false, "nuclei taramasını atla")
	severity := fs.String("severity", "", "nuclei severity override")
	noGAU := fs.Bool("no-gau", false, "gau/wayback pasif URL modülünü atla")
	noHeaders := fs.Bool("no-headers", false, "CORS/security header analizini atla")
	resume := fs.Bool("resume", false, "reuse completed Go checkpoint steps")
	resetResume := fs.Bool("reset-resume", false, "delete Go checkpoint before running")
	labMode := fs.Bool("lab-mode", false, "allow loopback/private IP targets for authorized local lab testing only")
	noSubenum := fs.Bool("no-subenum", false, "crt.sh/assetfinder pasif subdomain kaynaklarını atla")
	noBuckets := fs.Bool("no-buckets", false, "cloud bucket exposure tespitini atla")
	pruneDead := fs.Bool("prune-dead", false, "pasif URL'leri httpx ile doğrulayıp ölü/404 olanları ele")
	katana := fs.Bool("katana", false, "katana ile aktif derin crawl (hedefe trafik üretir)")
	arjun := fs.Bool("arjun", false, "arjun ile gizli parametre keşfi (hedefe trafik üretir)")
	xss := fs.Bool("xss", false, "dalfox ile aktif XSS tespiti (parametreli URL'lere probe payload gönderir)")
	dast := fs.Bool("dast", false, "nuclei -dast fuzzing (aktif; -no-nuclei ile birlikte kullanılamaz)")
	h1User := fs.String("h1-user", "", "HackerOne username for X-HackerOne-Research header")
	researchHeader := fs.String("research-header", "", "custom research attribution header name")
	_ = fs.Parse(args)

	if *target == "" {
		fatal("target gerekli")
	}

	// Sinyal ile iptal edilebilir context — FIX: graceful shutdown
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if *h1User != "" {
		_ = os.Setenv("RECONIXIA_H1_USERNAME", *h1User)
	}
	if *researchHeader != "" {
		_ = os.Setenv("RECONIXIA_RESEARCH_HEADER_NAME", *researchHeader)
	}
	if *labMode {
		_ = os.Setenv("RECONIXIA_LAB_MODE", "1")
		fmt.Println("[lab-mode] loopback/private targets enabled for local authorized lab only")
	}

	_, err := run(ctx, Options{
		Target:      *target,
		ScopeFile:   *scope,
		Profile:     *prof,
		SeedURL:     *seedURL,
		Wordlist:    *wordlist,
		NoNuclei:    *noNuclei,
		Severity:    *severity,
		NoGAU:       *noGAU,
		NoHeaders:   *noHeaders,
		Resume:      *resume,
		ResetResume: *resetResume,
		LabMode:     *labMode,
		NoSubenum:   *noSubenum,
		NoBuckets:   *noBuckets,
		PruneDead:   *pruneDead,
		Katana:      *katana,
		Arjun:       *arjun,
		XSS:         *xss,
		DAST:        *dast,
	})
	if err != nil {
		fatal(err.Error())
	}
}

// ── Ana tarama akışı ─────────────────────────────────────────────────────────

func run(ctx context.Context, o Options) (*Report, error) {
	target, ok := safety.NormalizeTarget(o.Target)
	if !ok {
		return nil, fmt.Errorf("gecersiz veya guvenli olmayan hedef: %q", o.Target)
	}
	p := profile(o.Profile)
	if o.Severity == "" {
		o.Severity = defaultSeverity(p.Name)
	}
	return runResumable(ctx, o, target, p)
}
func ask(in *bufio.Reader, label, def string) string {
	if def != "" {
		fmt.Printf("%s [%s]: ", label, def)
	} else {
		fmt.Printf("%s: ", label)
	}
	t, _ := in.ReadString('\n')
	t = strings.TrimSpace(t)
	if t == "" {
		return def
	}
	return t
}

func getenv(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func fatal(s string) {
	fmt.Fprintln(os.Stderr, "hata:", s)
	os.Exit(1)
}
