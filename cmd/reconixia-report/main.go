package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Veyselyigit21/Reconixia/internal/htmlreport"
	"github.com/Veyselyigit21/Reconixia/internal/safety"
)

func main() {
	target := flag.String("target", "", "target domain")
	input := flag.String("input", "", "report.json path")
	output := flag.String("output", "", "report.html output path")
	labMode := flag.Bool("lab-mode", false, "allow localhost/private lab targets")
	flag.Parse()

	if *labMode {
		_ = os.Setenv("RECONIXIA_LAB_MODE", "1")
	}

	in := strings.TrimSpace(*input)
	out := strings.TrimSpace(*output)

	if in == "" {
		if *target == "" {
			fmt.Fprintln(os.Stderr, "hata: -target veya -input gerekli")
			os.Exit(1)
		}
		t, ok := safety.NormalizeTarget(*target)
		if !ok {
			fmt.Fprintln(os.Stderr, "hata: gecersiz hedef")
			os.Exit(1)
		}
		in = filepath.Join("results", t, "report.json")
		if out == "" {
			out = filepath.Join("results", t, "report.html")
		}
	}

	if err := htmlreport.RenderFromJSON(in, out); err != nil {
		fmt.Fprintln(os.Stderr, "hata:", err)
		os.Exit(1)
	}
	fmt.Println("HTML rapor olusturuldu:", out)
}
