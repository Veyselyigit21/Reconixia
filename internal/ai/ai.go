package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/Veyselyigit21/Reconixia/internal/aianalysis"
	"github.com/Veyselyigit21/Reconixia/internal/redact"
)

type Config struct {
	Provider      string
	Model         string
	APIKey        string
	Endpoint      string
	OpenRouterRef string
	AppTitle      string
	MaxChunkChars int
	Timeout       time.Duration
}

func ConfigFromEnv(provider, model string) Config {
	p := strings.ToLower(strings.TrimSpace(provider))
	if p == "" {
		p = getenv("RECONIXIA_AI_PROVIDER", "local")
	}
	p = strings.ToLower(strings.TrimSpace(p))
	cfg := Config{
		Provider:      p,
		Model:         strings.TrimSpace(model),
		OpenRouterRef: getenv("OPENROUTER_SITE_URL", "https://github.com/Veyselyigit21/Reconixia"),
		AppTitle:      getenv("OPENROUTER_APP_TITLE", "Reconixia"),
		MaxChunkChars: envInt("RECONIXIA_AI_CHUNK_CHARS", 24000),
		Timeout:       time.Duration(envInt("RECONIXIA_AI_TIMEOUT_SECONDS", 90)) * time.Second,
	}
	switch p {
	case "local":
		cfg.Model = "local-keyword"
	case "openrouter":
		cfg.APIKey = os.Getenv("OPENROUTER_API_KEY")
		cfg.Model = firstNonEmpty(cfg.Model, getenv("OPENROUTER_MODEL", "deepseek/deepseek-r1"))
		cfg.Endpoint = getenv("OPENROUTER_ENDPOINT", "https://openrouter.ai/api/v1/chat/completions")
	case "openai":
		cfg.APIKey = os.Getenv("OPENAI_API_KEY")
		cfg.Model = firstNonEmpty(cfg.Model, getenv("OPENAI_MODEL", "gpt-4o-mini"))
		cfg.Endpoint = getenv("OPENAI_ENDPOINT", "https://api.openai.com/v1/chat/completions")
	case "deepseek":
		cfg.APIKey = os.Getenv("DEEPSEEK_API_KEY")
		cfg.Model = firstNonEmpty(cfg.Model, getenv("DEEPSEEK_MODEL", "deepseek-reasoner"))
		cfg.Endpoint = getenv("DEEPSEEK_ENDPOINT", "https://api.deepseek.com/chat/completions")
	}
	if cfg.MaxChunkChars < 4000 {
		cfg.MaxChunkChars = 4000
	}
	return cfg
}

func AnalyzeReport(ctx context.Context, cfg Config, report string) (aianalysis.Output, error) {
	cfg.Provider = strings.ToLower(strings.TrimSpace(cfg.Provider))
	if cfg.Provider == "" {
		cfg.Provider = "local"
	}
	cleanReport := redact.String(report)
	if cfg.Provider == "local" {
		return aianalysis.Local(cleanReport), nil
	}
	if cfg.APIKey == "" {
		return aianalysis.Output{}, fmt.Errorf("%s API key yok", cfg.Provider)
	}
	if cfg.Endpoint == "" || cfg.Model == "" {
		return aianalysis.Output{}, fmt.Errorf("%s provider config eksik", cfg.Provider)
	}
	chunks := ChunkReport(cleanReport, cfg.MaxChunkChars)
	outputs := make([]aianalysis.Output, 0, len(chunks))
	warnings := []string{}
	for i, chunk := range chunks {
		prompt := fmt.Sprintf("Report chunk %d/%d. Return exactly one JSON object matching the schema. No markdown, no prose, no code fences.\n\n%s", i+1, len(chunks), chunk)
		out, err := askStructured(ctx, cfg, prompt)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("chunk %d/%d failed: %v", i+1, len(chunks), err))
			continue
		}
		outputs = append(outputs, out)
	}
	if len(outputs) == 0 {
		fallback := aianalysis.Local(cleanReport)
		fallback.Summary = fmt.Sprintf("%s provider JSON analysis failed; local fallback generated from recon keywords.", cfg.Provider)
		fallback.Warnings = append(redact.Strings(warnings), fallback.Warnings...)
		return fallback, nil
	}
	return aggregate(outputs, warnings), nil
}

func ChunkReport(report string, maxChars int) []string {
	report = redact.String(report)
	if maxChars <= 0 || len(report) <= maxChars {
		return []string{report}
	}
	lines := strings.Split(report, "\n")
	chunks := []string{}
	var current strings.Builder
	for _, line := range lines {
		if current.Len()+len(line)+1 > maxChars && current.Len() > 0 {
			chunks = append(chunks, strings.TrimSpace(current.String()))
			current.Reset()
		}
		if len(line) > maxChars {
			for len(line) > maxChars {
				chunks = append(chunks, line[:maxChars])
				line = line[maxChars:]
			}
		}
		current.WriteString(line)
		current.WriteByte('\n')
	}
	if strings.TrimSpace(current.String()) != "" {
		chunks = append(chunks, strings.TrimSpace(current.String()))
	}
	if len(chunks) == 0 {
		return []string{""}
	}
	return chunks
}

func Markdown(out aianalysis.Output) string {
	var b strings.Builder
	b.WriteString("# Reconixia AI Analysis\n\n")
	if out.Summary != "" {
		b.WriteString(out.Summary + "\n\n")
	}
	if len(out.Warnings) > 0 {
		b.WriteString("## Warnings\n\n")
		for _, w := range out.Warnings {
			b.WriteString("- " + redact.String(w) + "\n")
		}
		b.WriteString("\n")
	}
	b.WriteString("## Findings\n\n")
	if len(out.Items) == 0 {
		b.WriteString("- No prioritized AI findings.\n")
		return b.String()
	}
	for _, item := range out.Items {
		b.WriteString(fmt.Sprintf("- **%s** `%s/%s`", redact.String(item.Title), item.Priority, item.Confidence))
		if item.Asset != "" {
			b.WriteString(" - `" + redact.String(item.Asset) + "`")
		}
		if item.Reportability != "" {
			b.WriteString(" - " + item.Reportability)
		}
		b.WriteString("\n")
		if item.Impact != "" {
			b.WriteString("  Impact: " + redact.String(item.Impact) + "\n")
		} else if item.WhyItMatters != "" {
			b.WriteString("  Impact: " + redact.String(item.WhyItMatters) + "\n")
		}
		if item.NextStep != "" {
			b.WriteString("  Next: " + redact.String(item.NextStep) + "\n")
		} else if len(item.NextSteps) > 0 {
			b.WriteString("  Next: " + redact.String(item.NextSteps[0]) + "\n")
		}
	}
	return b.String()
}

func askStructured(ctx context.Context, cfg Config, user string) (aianalysis.Output, error) {
	payload := map[string]any{
		"model": cfg.Model,
		"messages": []map[string]string{
			{"role": "system", "content": aianalysis.SystemPrompt()},
			{"role": "user", "content": redact.String(user)},
		},
		"temperature": 0.2,
		"response_format": map[string]string{
			"type": "json_object",
		},
	}
	raw, _ := json.Marshal(payload)
	client := &http.Client{Timeout: cfg.Timeout}
	if cfg.Timeout == 0 {
		client.Timeout = 90 * time.Second
	}
	var lastErr error
	backoff := 2 * time.Second
	for attempt := 0; attempt < 4; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return aianalysis.Output{}, ctx.Err()
			case <-time.After(backoff):
				backoff *= 2
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.Endpoint, bytes.NewReader(raw))
		if err != nil {
			return aianalysis.Output{}, err
		}
		req.Header.Set("Authorization", "Bearer "+cfg.APIKey)
		req.Header.Set("Content-Type", "application/json")
		if cfg.Provider == "openrouter" {
			req.Header.Set("HTTP-Referer", cfg.OpenRouterRef)
			req.Header.Set("X-Title", cfg.AppTitle)
		}
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 4_000_000))
		resp.Body.Close()
		if readErr != nil {
			lastErr = readErr
			continue
		}
		if retryable(resp.StatusCode) {
			lastErr = fmt.Errorf("HTTP %d: %s", resp.StatusCode, redact.String(string(body)))
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return aianalysis.Output{}, fmt.Errorf("HTTP %d: %s", resp.StatusCode, redact.String(string(body)))
		}
		content, err := chatContent(body)
		if err != nil {
			return aianalysis.Output{}, err
		}
		out, err := ParseOutput(content)
		if err != nil {
			return aianalysis.Output{}, fmt.Errorf("%w; response preview: %s", err, compactPreview(content, 300))
		}
		return out, nil
	}
	return aianalysis.Output{}, fmt.Errorf("AI API basarisiz: %v", lastErr)
}

func ParseOutput(content string) (aianalysis.Output, error) {
	content = redact.String(strings.TrimSpace(content))
	content = strings.TrimPrefix(content, "```json")
	content = strings.TrimPrefix(content, "```")
	content = strings.TrimSuffix(content, "```")
	start := strings.Index(content, "{")
	end := strings.LastIndex(content, "}")
	if start < 0 || end < start {
		return aianalysis.Output{}, fmt.Errorf("AI response JSON degil")
	}
	var out aianalysis.Output
	if err := json.Unmarshal([]byte(content[start:end+1]), &out); err != nil {
		return aianalysis.Output{}, err
	}
	out.GeneratedAt = time.Now().Format(time.RFC3339)
	for i := range out.Items {
		out.Items[i].Title = redact.String(out.Items[i].Title)
		out.Items[i].Asset = cleanAsset(out.Items[i].Asset)
		out.Items[i].Impact = redact.String(out.Items[i].Impact)
		out.Items[i].WhyItMatters = redact.String(out.Items[i].WhyItMatters)
		out.Items[i].NextStep = sanitizeGuidance(out.Items[i].NextStep)
		out.Items[i].Evidence = redact.Strings(out.Items[i].Evidence)
		for j := range out.Items[i].NextSteps {
			out.Items[i].NextSteps[j] = sanitizeGuidance(out.Items[i].NextSteps[j])
		}
		downgradeLowSignal(&out.Items[i])
	}
	out.Warnings = redact.Strings(out.Warnings)
	return out, nil
}

func chatContent(body []byte) (string, error) {
	var parsed struct {
		Choices []struct {
			Message struct {
				Content   string `json:"content"`
				Reasoning string `json:"reasoning"`
				Refusal   string `json:"refusal"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", err
	}
	if len(parsed.Choices) == 0 {
		return "", fmt.Errorf("AI response choices bos")
	}
	msg := parsed.Choices[0].Message
	if strings.TrimSpace(msg.Content) != "" {
		return msg.Content, nil
	}
	if strings.TrimSpace(msg.Reasoning) != "" {
		return msg.Reasoning, nil
	}
	if strings.TrimSpace(msg.Refusal) != "" {
		return msg.Refusal, nil
	}
	return "", fmt.Errorf("AI response content bos")
}

func cleanAsset(asset string) string {
	asset = redact.String(strings.TrimSpace(asset))
	asset = strings.Trim(asset, "`[](),.;")
	for {
		next := strings.TrimSuffix(asset, "%60")
		next = strings.TrimSuffix(next, "`")
		if next == asset {
			return next
		}
		asset = next
	}
}

func downgradeLowSignal(item *aianalysis.Item) {
	text := strings.ToLower(item.Title + " " + item.Asset + " " + item.Category)
	isRouteOnly := strings.Contains(text, "/login") ||
		strings.Contains(text, "/dashboard") ||
		strings.Contains(text, "authentication surface") ||
		strings.Contains(text, "login page")
	isKnownLowSignal := strings.Contains(text, "robots.txt") ||
		strings.Contains(text, "sitemap.xml") ||
		strings.Contains(text, "missing referrer") ||
		strings.Contains(text, "referrer-policy") ||
		strings.Contains(text, "403") ||
		strings.Contains(text, "/static")
	if item.Reportability == "likely_reportable" && isRouteOnly {
		item.Reportability = "needs_manual_validation"
		item.Confidence = lowerConfidence(item.Confidence, "medium")
		item.NextStep = "Verify whether there is a concrete authorization bypass or sensitive data exposure; route existence alone is not reportable."
	}
	if isKnownLowSignal {
		if item.Reportability == "likely_reportable" || item.Reportability == "needs_manual_validation" {
			item.Reportability = "low_signal"
		}
		item.Priority = lowerPriority(item.Priority, "low")
	}
}

func sanitizeGuidance(s string) string {
	s = redact.String(strings.TrimSpace(s))
	lower := strings.ToLower(s)
	blocked := []string{"brute force", "bruteforce", "credential attack", "credential stuffing", "rate limiting", "rate limit", "dos", "denial of service"}
	for _, term := range blocked {
		if strings.Contains(lower, term) {
			return "Verify login and authorization behavior manually with authorized accounts only; do not run high-volume auth, availability, or production automation tests."
		}
	}
	return s
}

func compactPreview(s string, max int) string {
	s = redact.String(strings.Join(strings.Fields(s), " "))
	if max <= 0 || len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

func lowerConfidence(current, ceiling string) string {
	if confidenceRank(current) > confidenceRank(ceiling) {
		return ceiling
	}
	return current
}

func confidenceRank(confidence string) int {
	switch strings.ToLower(confidence) {
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func lowerPriority(current, ceiling string) string {
	if priorityRank(current) < priorityRank(ceiling) {
		return ceiling
	}
	return current
}

func aggregate(outputs []aianalysis.Output, warnings []string) aianalysis.Output {
	out := aianalysis.Output{
		GeneratedAt: time.Now().Format(time.RFC3339),
		Summary:     fmt.Sprintf("AI analysis aggregated from %d report chunk(s).", len(outputs)),
		Warnings:    redact.Strings(warnings),
	}
	seen := map[string]bool{}
	for _, chunk := range outputs {
		if chunk.Summary != "" {
			out.Warnings = append(out.Warnings, "chunk summary: "+redact.String(chunk.Summary))
		}
		for _, item := range chunk.Items {
			key := strings.ToLower(item.Title + "|" + item.Asset + "|" + item.Category)
			if seen[key] {
				continue
			}
			seen[key] = true
			out.Items = append(out.Items, item)
		}
		out.Warnings = append(out.Warnings, redact.Strings(chunk.Warnings)...)
	}
	sort.SliceStable(out.Items, func(i, j int) bool {
		return priorityRank(out.Items[i].Priority) < priorityRank(out.Items[j].Priority)
	})
	return out
}

func retryable(status int) bool {
	switch status {
	case 429, 500, 502, 503, 504:
		return true
	default:
		return false
	}
}

func priorityRank(priority string) int {
	switch strings.ToLower(priority) {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	default:
		return 4
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func getenv(k, d string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return d
}

func envInt(k string, d int) int {
	var parsed int
	if _, err := fmt.Sscanf(os.Getenv(k), "%d", &parsed); err == nil && parsed > 0 {
		return parsed
	}
	return d
}
