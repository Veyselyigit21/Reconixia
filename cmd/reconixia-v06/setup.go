package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/exec"
	"sort"
	"strings"
)

func setup() {
	in := bufio.NewReader(os.Stdin)
	env := readEnv()
	for {
		fmt.Println("\nReconixia Kurulum Menüsü")
		fmt.Println("1) AI sağlayıcısı / model / API key ayarla")
		fmt.Println("2) Kayıtlı ayarları göster")
		fmt.Println("3) Kaydet ve çık")
		fmt.Println("0) Çıkış")
		switch ask(in, "Seçim", "") {
		case "1":
			setupAI(in, env)
		case "2":
			printEnv(env)
		case "3":
			writeEnv(env)
			return
		case "0":
			return
		}
	}
}

func setupAI(in *bufio.Reader, env map[string]string) {
	fmt.Println("1) Local\n2) OpenRouter\n3) OpenAI\n4) DeepSeek\n0) Geri")
	switch ask(in, "Seçim", "") {
	case "1":
		env["RECONIXIA_AI_PROVIDER"] = "local"
	case "2":
		env["RECONIXIA_AI_PROVIDER"] = "openrouter"
		askSecret(in, env, "OPENROUTER_API_KEY", "OpenRouter key")
		askValue(in, env, "OPENROUTER_MODEL", "Model", "deepseek/deepseek-r1")
	case "3":
		env["RECONIXIA_AI_PROVIDER"] = "openai"
		askSecret(in, env, "OPENAI_API_KEY", "OpenAI key")
		askValue(in, env, "OPENAI_MODEL", "Model", "gpt-4o-mini")
	case "4":
		env["RECONIXIA_AI_PROVIDER"] = "deepseek"
		askSecret(in, env, "DEEPSEEK_API_KEY", "DeepSeek key")
		askValue(in, env, "DEEPSEEK_MODEL", "Model", "deepseek-reasoner")
	}
}

func loadEnv() {
	for k, v := range readEnv() {
		if os.Getenv(k) == "" {
			_ = os.Setenv(k, v)
		}
	}
}

func readEnv() map[string]string {
	m := map[string]string{
		"RECONIXIA_AI_PROVIDER": "local",
		"OPENROUTER_MODEL":      "deepseek/deepseek-r1",
		"OPENAI_MODEL":          "gpt-4o-mini",
		"DEEPSEEK_MODEL":        "deepseek-reasoner",
	}
	f, err := os.Open(".env")
	if err != nil {
		return m
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || !strings.Contains(line, "=") {
			continue
		}
		p := strings.SplitN(line, "=", 2)
		m[strings.TrimSpace(p[0])] = strings.Trim(strings.TrimSpace(p[1]), "\"")
	}
	return m
}

func writeEnv(m map[string]string) {
	keys := []string{}
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	// FIX: Uyarı mesajı düzeltildi
	b.WriteString("# Reconixia configuration\n")
	b.WriteString("# UYARI: Bu dosyayı GitHub'a veya herhangi bir repo'ya YUKLEMEYİN — API key içerir!\n\n")
	for _, k := range keys {
		b.WriteString(k + "=" + m[k] + "\n")
	}
	if err := os.WriteFile(".env", []byte(b.String()), 0600); err != nil {
		log.Printf("[WARN] .env yazılamadı: %v", err)
		return
	}
	loadEnv()
	fmt.Println("Ayarlar kaydedildi: .env")
}

func printEnv(m map[string]string) {
	for _, k := range []string{"RECONIXIA_AI_PROVIDER", "OPENROUTER_API_KEY", "OPENAI_API_KEY", "DEEPSEEK_API_KEY"} {
		v := m[k]
		if strings.Contains(k, "KEY") {
			v = mask(v)
		}
		if v == "" {
			v = "boş"
		}
		fmt.Println(k, "=", v)
	}
}

func mask(s string) string {
	if s == "" {
		return "boş"
	}
	if len(s) < 9 {
		return "********"
	}
	return s[:4] + "..." + s[len(s)-4:]
}

func askSecret(in *bufio.Reader, m map[string]string, k, label string) {
	v := ask(in, label+" ["+mask(m[k])+"]", "")
	if v != "" {
		m[k] = v
	}
}

func askValue(in *bufio.Reader, m map[string]string, k, label, def string) {
	if m[k] != "" {
		def = m[k]
	}
	v := ask(in, label, def)
	if v != "" {
		m[k] = v
	}
}

func doctor() {
	for _, b := range []string{"go", "git", "subfinder", "httpx", "nuclei", "gau"} {
		if _, err := exec.LookPath(b); err == nil {
			fmt.Println("[OK]", b)
		} else {
			fmt.Println("[YOK]", b)
		}
	}
	for _, e := range []string{"OPENROUTER_API_KEY", "OPENAI_API_KEY", "DEEPSEEK_API_KEY"} {
		if os.Getenv(e) != "" {
			fmt.Println("[OK]", e)
		} else {
			fmt.Println("[YOK]", e, "(opsiyonel)")
		}
	}
}

// ── Wordlist / dosya yardımcıları ────────────────────────────────────────────
