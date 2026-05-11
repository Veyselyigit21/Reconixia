package secrets

import (
	"regexp"
	"sort"
)

type Match struct {
	Type       string `json:"type"`
	Confidence string `json:"confidence"`
	Note       string `json:"note"`
}

type Pattern struct {
	Type       string
	Confidence string
	Note       string
	Re         *regexp.Regexp
}

var defaultPatterns = []Pattern{
	{Type: "possible_aws_access_key", Confidence: "high", Note: "AWS access key format detected; verify exposure and permissions manually", Re: regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)},
	{Type: "possible_aws_temp_key", Confidence: "medium", Note: "AWS temporary access key format detected", Re: regexp.MustCompile(`\bASIA[0-9A-Z]{16}\b`)},
	{Type: "possible_aws_secret_assignment", Confidence: "medium", Note: "AWS secret key assignment-like pattern detected", Re: regexp.MustCompile(`(?i)(aws_secret_access_key|aws_secret_key|secretaccesskey)[\s:=\"']{1,8}[A-Za-z0-9/+=]{30,}`)},
	{Type: "possible_github_token", Confidence: "high", Note: "GitHub token-like value detected", Re: regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9_]{20,}\b`)},
	{Type: "possible_github_fine_grained_token", Confidence: "high", Note: "GitHub fine-grained token-like value detected", Re: regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{20,}\b`)},
	{Type: "possible_gitlab_token", Confidence: "medium", Note: "GitLab token-like value detected", Re: regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{20,}\b`)},
	{Type: "possible_google_api_key", Confidence: "medium", Note: "Google API key-like value detected", Re: regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`)},
	{Type: "possible_google_oauth_client_secret", Confidence: "medium", Note: "Google OAuth client secret-like value detected", Re: regexp.MustCompile(`\bGOCSPX-[0-9A-Za-z_-]{20,}\b`)},
	{Type: "possible_openai_key", Confidence: "high", Note: "OpenAI API key-like value detected", Re: regexp.MustCompile(`\bsk-[A-Za-z0-9]{20,}\b`)},
	{Type: "possible_openai_project_key", Confidence: "high", Note: "OpenAI project API key-like value detected", Re: regexp.MustCompile(`\bsk-proj-[A-Za-z0-9_-]{20,}\b`)},
	{Type: "possible_anthropic_key", Confidence: "high", Note: "Anthropic API key-like value detected", Re: regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_-]{20,}\b`)},
	{Type: "possible_slack_token", Confidence: "medium", Note: "Slack token-like value detected", Re: regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}\b`)},
	{Type: "possible_slack_webhook", Confidence: "medium", Note: "Slack webhook URL-like value detected", Re: regexp.MustCompile(`https://hooks\.slack\.com/services/[A-Za-z0-9_/.-]{20,}`)},
	{Type: "possible_stripe_secret_key", Confidence: "high", Note: "Stripe secret key-like value detected", Re: regexp.MustCompile(`\bsk_(?:live|test)_[A-Za-z0-9]{20,}\b`)},
	{Type: "possible_stripe_restricted_key", Confidence: "medium", Note: "Stripe restricted key-like value detected", Re: regexp.MustCompile(`\brk_(?:live|test)_[A-Za-z0-9]{20,}\b`)},
	{Type: "possible_sendgrid_key", Confidence: "medium", Note: "SendGrid API key-like value detected", Re: regexp.MustCompile(`\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b`)},
	{Type: "possible_mailgun_key", Confidence: "medium", Note: "Mailgun API key-like value detected", Re: regexp.MustCompile(`\bkey-[0-9a-fA-F]{32}\b`)},
	{Type: "possible_twilio_sid", Confidence: "low", Note: "Twilio SID-like value detected", Re: regexp.MustCompile(`\bAC[0-9a-fA-F]{32}\b`)},
	{Type: "possible_firebase_url", Confidence: "low", Note: "Firebase database URL-like value detected", Re: regexp.MustCompile(`https://[a-z0-9-]+\.firebaseio\.com`)},
	{Type: "possible_private_key_block", Confidence: "high", Note: "Private key block marker detected", Re: regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----`)},
	{Type: "possible_jwt", Confidence: "low", Note: "JWT-like value detected; may be benign", Re: regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`)},
	{Type: "possible_basic_auth_url", Confidence: "medium", Note: "URL with embedded credentials detected", Re: regexp.MustCompile(`https?://[^\s/@:]+:[^\s/@]+@[^\s]+`)},
	{Type: "possible_generic_secret_assignment", Confidence: "low", Note: "Generic secret/token assignment detected; manual false-positive review required", Re: regexp.MustCompile(`(?i)(api[_-]?key|access[_-]?token|secret|client[_-]?secret|auth[_-]?token)[\s:=\"']{1,8}[A-Za-z0-9_\-./+=]{24,}`)},
}

func Scan(body string) []Match {
	seen := map[string]bool{}
	var out []Match
	for _, p := range defaultPatterns {
		if p.Re.MatchString(body) && !seen[p.Type] {
			seen[p.Type] = true
			out = append(out, Match{Type: p.Type, Confidence: p.Confidence, Note: p.Note})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Type < out[j].Type })
	return out
}
