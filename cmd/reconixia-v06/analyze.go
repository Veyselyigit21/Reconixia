package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	aipkg "github.com/Veyselyigit21/Reconixia/internal/ai"
	"github.com/Veyselyigit21/Reconixia/internal/aianalysis"
	"github.com/Veyselyigit21/Reconixia/internal/redact"
	"github.com/Veyselyigit21/Reconixia/internal/safety"
)

func cmdAnalyze(args []string) {
	fs := flag.NewFlagSet("analyze", flag.ExitOnError)
	target := fs.String("target", "", "target domain")
	input := fs.String("input", "", "report.md path")
	output := fs.String("output", "", "ai_analysis.json path")
	provider := fs.String("provider", getenv("RECONIXIA_AI_PROVIDER", "local"), "local|openrouter|openai|deepseek")
	model := fs.String("model", "", "model override")
	labMode := fs.Bool("lab-mode", false, "allow localhost/private lab targets")
	_ = fs.Parse(args)
	if *labMode {
		_ = os.Setenv("RECONIXIA_LAB_MODE", "1")
	}
	if *target == "" && *input == "" {
		fatal("target veya input gerekli")
	}
	if err := analyzeWithOptions(*target, *input, *output, *provider, *model); err != nil {
		fatal(err.Error())
	}
}

func analyze(target, provider, model string) error {
	return analyzeWithOptions(target, "", "", provider, model)
}

func analyzeWithOptions(target, input, output, provider, model string) error {
	var workspace string
	if input == "" {
		t, ok := safety.NormalizeTarget(target)
		if !ok {
			return fmt.Errorf("gecersiz hedef")
		}
		workspace = filepath.Join("results", t)
		input = filepath.Join(workspace, "report.md")
	} else if target != "" {
		if t, ok := safety.NormalizeTarget(target); ok {
			workspace = filepath.Join("results", t)
		}
	}
	if output == "" {
		if workspace == "" {
			output = "ai_analysis.json"
		} else {
			output = filepath.Join(workspace, "ai_analysis.json")
		}
	}
	raw, err := os.ReadFile(input)
	if err != nil {
		return fmt.Errorf("rapor okunamadi: %w", err)
	}
	reportText := string(raw)
	if workspace != "" && filepath.Base(input) == "report.md" {
		if idorRaw, err := os.ReadFile(filepath.Join(workspace, "idor_analysis.md")); err == nil && len(idorRaw) > 0 {
			reportText += "\n\n---\n\n" + string(idorRaw)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()
	cfg := aipkg.ConfigFromEnv(provider, model)
	result, err := aipkg.AnalyzeReport(ctx, cfg, redact.String(reportText))
	if err != nil {
		return err
	}
	jsonOut := aianalysis.ToJSON(result) + "\n"
	if err := os.MkdirAll(filepath.Dir(output), 0700); err != nil && filepath.Dir(output) != "." {
		return err
	}
	if err := os.WriteFile(output, []byte(jsonOut), 0600); err != nil {
		return err
	}
	markdownOut := aipkg.Markdown(result)
	mdPath := filepath.Join(filepath.Dir(output), "ai_analysis.md")
	if err := os.WriteFile(mdPath, []byte(markdownOut), 0600); err != nil {
		return err
	}
	fmt.Println(markdownOut)
	fmt.Println("[+] AI JSON:", output)
	fmt.Println("[+] AI Markdown:", mdPath)
	return nil
}
