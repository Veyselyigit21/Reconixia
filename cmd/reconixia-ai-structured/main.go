package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Veyselyigit21/Reconixia/internal/aianalysis"
	"github.com/Veyselyigit21/Reconixia/internal/safety"
)

func main() {
	target := flag.String("target", "", "target domain")
	input := flag.String("input", "", "input report markdown")
	output := flag.String("output", "", "output json path")
	flag.Parse()

	if *target == "" && *input == "" {
		fatal("target or input required")
	}

	if *input == "" {
		t, ok := safety.NormalizeTarget(*target)
		if !ok {
			fatal("invalid target")
		}
		*input = filepath.Join("results", t, "report.md")
		if *output == "" {
			*output = filepath.Join("results", t, "ai_analysis.json")
		}
	}
	if *output == "" {
		*output = "ai_analysis.json"
	}

	raw, err := os.ReadFile(*input)
	if err != nil {
		fatal(err.Error())
	}
	result := aianalysis.Local(string(raw))
	jsonOut := aianalysis.ToJSON(result)

	outDir := filepath.Dir(*output)
	if outDir != "." && outDir != "" {
		if err := os.MkdirAll(outDir, 0755); err != nil {
			fatal(err.Error())
		}
	}
	if err := os.WriteFile(*output, []byte(jsonOut+"\n"), 0644); err != nil {
		fatal(err.Error())
	}
	fmt.Println(jsonOut)
	fmt.Println("[+] Structured analysis written:", *output)
}

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, "error:", msg)
	os.Exit(1)
}
