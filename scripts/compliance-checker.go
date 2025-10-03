package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

type LLMRequest struct {
	Messages    []LLMMessage `json:"messages"`
	Temperature float64      `json:"temperature,omitempty"`
	TopP        float64      `json:"top_p,omitempty"`
	MaxTokens   int          `json:"max_tokens,omitempty"`
}

type LLMMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type LLMResponse struct {
	Choices []struct {
		Message struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
}

type Finding struct {
	File       string `json:"file"`
	Signal     string `json:"signal"`
	Snippet    string `json:"snippet,omitempty"`
	Confidence string `json:"confidence"`
}

type SecretHit struct {
	File    string `json:"file"`
	Line    int    `json:"line"`
	Kind    string `json:"kind"`
	Snippet string `json:"snippet"`
}

type Collected struct {
	FilesScanned int         `json:"files_scanned"`
	Findings     []Finding   `json:"findings"`
	Secrets      []SecretHit `json:"secrets"`
	ExcerptPack  string      `json:"excerpt_pack"`
}

const systemPrompt = `You are a senior compliance analyst.
Scope:
- Assess repository-level evidence related to GDPR and ISO/IEC 27001:2022 (Annex A) as observable in code, configs, docs, CI/CD.
- Do NOT give legal advice. Base judgments ONLY on the provided content.
- Prefer "Unknown" when evidence is missing.

Deliver two artifacts:
1) STRICT JSON "compliance" with this schema (no markdown, no prose outside JSON):
{
  "gdpr": [
    {"article":"5","title":"Principles","status":"Compliant|NonCompliant|Unknown","evidence":["path#Lx-..."],"risk":"low|medium|high","recommendation": "…"},
    {"article":"6","title":"Lawfulness","status": "...", "evidence":[...], "risk":"...", "recommendation":"..."},
    {"article":"13","title":"Information to data subjects",...},
    {"article":"25","title":"Privacy by design/default",...},
    {"article":"30","title":"Records of processing",...},
    {"article":"32","title":"Security of processing",...},
    {"article":"33","title":"Breach notification",...},
    {"article":"34","title":"Notify data subjects",...},
    {"article":"35","title":"DPIA",...},
    {"article":"44","title":"Transfers",...}
  ],
  "iso27001_annexA": [
    {"control":"A.5.1","title":"Policies for information security","status":"...", "evidence":[...], "risk":"...", "recommendation":"..."},
    {"control":"A.5.18","title":"Access control","status":"...", ...},
    {"control":"A.5.23","title":"Supplier relationships","status":"...", ...},
    {"control":"A.5.34","title":"Logging","status":"...", ...},
    {"control":"A.8.12","title":"Data leakage prevention","status":"...", ...},
    {"control":"A.8.16","title":"Monitoring activities","status":"...", ...},
    {"control":"A.8.22","title":"Secure coding","status":"...", ...},
    {"control":"A.8.23","title":"Security testing","status":"...", ...},
    {"control":"A.8.24","title":"System acceptance","status":"...", ...}
  ],
  "overall": {
    "status":"Compliant|Partially Compliant|NonCompliant|Unknown",
    "top_risks":[{"item":"...", "why":"...", "impact":"...", "likelihood":"low|med|high"}],
    "quick_wins":["...","..."],
    "gaps":["...","..."]
  }
}

2) Short plain-text "summary" (<= 1600 chars) giving a prioritized action list for engineers (no legalese), referencing file paths when possible.

Rules:
- Use only info in "COLLECTED_EVIDENCE" below. If you infer, label as "inference".
- Evidence paths should be specific (file names; line numbers only if present in Snippets).
- Prefer conservative ratings; absence of docs/policies ⇒ "Unknown" (not "NonCompliant") unless there is contrary evidence.
`

// Minimal heuristic secret patterns (extend as needed)
var secretRegexes = map[string]*regexp.Regexp{
	"Generic API key":    regexp.MustCompile(`(?i)(api[_-]?key|token|secret|pwd|password)\s*[:=]\s*["']?[A-Za-z0-9_\-]{16,}`),
	"AWS Access Key ID":  regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	"Google API Key":     regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`),
	"Slack Token":        regexp.MustCompile(`xox[baprs]-[0-9A-Za-z\-]{10,}`),
	"Stripe Key":         regexp.MustCompile(`sk_live_[0-9A-Za-z]{20,}`),
	"Private Key Header": regexp.MustCompile(`-----BEGIN (RSA|EC|OPENSSH|PGP) PRIVATE KEY-----`),
}

var allowedExt = map[string]bool{
	".md": true, ".txt": true, ".rst": true,
	".yaml": true, ".yml": true, ".json": true,
	".tf": true, ".tfvars": true, ".hcl": true,
	".sh": true, ".ps1": true, ".bash": true, ".zsh": true,
	".py": true, ".go": true, ".js": true, ".ts": true, ".tsx": true,
	".dockerfile": true,
}

var ignoreDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, "dist": true, "build": true, "bin": true, ".venv": true, ".tox": true, ".idea": true, ".vscode": true,
}

func main() {
	var (
		endpoint      = flag.String("azure-endpoint", os.Getenv("AZURE_OPENAI_ENDPOINT"), "Azure OpenAI endpoint, e.g. https://<resource>.openai.azure.com")
		deployment    = flag.String("azure-deployment", os.Getenv("AZURE_OPENAI_DEPLOYMENT"), "Azure OpenAI deployment name (chat model)")
		apiKey        = flag.String("azure-api-key", os.Getenv("AZURE_OPENAI_API_KEY"), "Azure OpenAI API key")
		apiVersion    = flag.String("api-version", getenvDefault("AZURE_OPENAI_API_VERSION", "2024-02-15-preview"), "API version")
		maxFiles      = flag.Int("max-files", 250, "Max files to scan")
		perFileBytes  = flag.Int("per-file-bytes", 200*1024, "Max bytes per file to include")
		totalBytesCap = flag.Int("total-bytes-cap", 800*1024, "Max total bytes to include in LLM prompt")
		maxTokens     = flag.Int("max-tokens", 1500, "Max tokens for LLM response")
		timeoutSec    = flag.Int("timeout", 60, "HTTP timeout seconds")
		dryRun        = flag.Bool("dry-run", false, "Skip LLM call; print collected evidence JSON")
	)
	flag.Parse()

	if *endpoint == "" || *deployment == "" || *apiKey == "" {
		if !*dryRun {
			fmt.Println("⚠️  Variables requises manquantes. Utilise les flags ou ces env vars:")
			fmt.Println("   AZURE_OPENAI_ENDPOINT, AZURE_OPENAI_DEPLOYMENT, AZURE_OPENAI_API_KEY, (optionnel) AZURE_OPENAI_API_VERSION")
			fmt.Println("   Astuce: lance d'abord en --dry-run pour vérifier la collecte.")
			os.Exit(2)
		}
	}

	collected, err := collectRepo(*maxFiles, *perFileBytes, *totalBytesCap)
	if err != nil {
		fail(err)
	}

	if *dryRun {
		b, _ := json.MarshalIndent(collected, "", "  ")
		fmt.Println(string(b))
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(*timeoutSec)*time.Second)
	defer cancel()

	respContent, err := callAzureChat(ctx, *endpoint, *deployment, *apiVersion, *apiKey, buildPrompt(collected), *maxTokens)
	if err != nil {
		fail(err)
	}

	// Try to split JSON + summary if model appended both
	jsonPart, summary := splitJsonAndSummary(respContent)

	// Parse JSON
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(jsonPart), &parsed); err != nil {
		fmt.Println("Réponse LLM (brute; JSON non valide détecté):\n")
		fmt.Println(respContent)
		os.Exit(1)
	}

	// Pretty print
	fmt.Println("=== GDPR & ISO/IEC 27001 – Résumé exécutable ===")
	if summary != "" {
		fmt.Println(summary)
		fmt.Println()
	}

	fmt.Println("=== Rapport JSON structuré ===")
	var pretty bytes.Buffer
	json.Indent(&pretty, []byte(jsonPart), "", "  ")
	fmt.Println(pretty.String())
}

func collectRepo(maxFiles, perFileBytes, totalBytesCap int) (*Collected, error) {
	col := &Collected{}
	var excerpts []string
	files := []string{}

	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			base := filepath.Base(path)
			if ignoreDirs[base] {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasPrefix(path, ".git/") {
			return nil
		}

		base := strings.ToLower(filepath.Base(path))
		ext := strings.ToLower(filepath.Ext(path))

		if isInteresting(base, ext) {
			files = append(files, path)
			if len(files) >= maxFiles {
				return io.EOF // stop walking
			}
		}
		return nil
	})
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}

	sort.Strings(files)
	col.FilesScanned = len(files)

	// Collect findings + secrets
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		content := string(b)
		// Secret scan (line-by-line)
		lines := strings.Split(content, "\n")
		for i, line := range lines {
			for kind, re := range secretRegexes {
				if re.MatchString(line) {
					col.Secrets = append(col.Secrets, SecretHit{
						File: f, Line: i + 1, Kind: kind, Snippet: truncate(line, 180),
					})
				}
			}
		}

		// Signals
		signal := classifySignal(f, content)
		if signal != "" {
			col.Findings = append(col.Findings, Finding{
				File:       f,
				Signal:     signal,
				Snippet:    sampleSnippet(content, 600),
				Confidence: "medium",
			})
		}

		if capReached(excerpts, totalBytesCap) {
			continue
		}
		excerpts = append(excerpts, fmt.Sprintf("\n--- FILE: %s ---\n%s", f, safeExcerpt(content, perFileBytes)))
	}
	col.ExcerptPack = strings.Join(excerpts, "\n")
	return col, nil
}

func isInteresting(base, ext string) bool {
	if allowedExt[ext] {
		return true
	}
	// Special names without extension
	names := []string{
		"dockerfile", "makefile", ".gitlab-ci.yml", ".github", "docker-compose.yml", "docker-compose.yaml",
		"security.md", "privacy.md", "privacy-policy.md", "data-processing-agreement.md",
		"readme.md", "architecture.md", "threat-model.md", "dpa.md",
		".env.example", ".env.template", "compose.yaml", "compose.yml",
	}
	for _, n := range names {
		if strings.EqualFold(base, n) {
			return true
		}
	}
	// policy files
	if strings.Contains(strings.ToLower(base), "privacy") ||
		strings.Contains(strings.ToLower(base), "security") ||
		strings.Contains(strings.ToLower(base), "retention") ||
		strings.Contains(strings.ToLower(base), "incident") ||
		strings.Contains(strings.ToLower(base), "backup") ||
		strings.Contains(strings.ToLower(base), "dpa") ||
		strings.Contains(strings.ToLower(base), "gdpr") ||
		strings.Contains(strings.ToLower(base), "rgpd") {
		return true
	}
	return false
}

func classifySignal(path, content string) string {
	p := strings.ToLower(path)
	switch {
	case strings.Contains(p, "security.md"):
		return "Security policy document"
	case strings.Contains(p, "privacy"):
		return "Privacy policy or notice"
	case strings.Contains(p, "incident") || strings.Contains(content, "incident"):
		return "Incident response doc"
	case strings.Contains(p, "backup") || strings.Contains(content, "backup"):
		return "Backup/DR reference"
	case strings.Contains(p, ".gitlab-ci.yml") || strings.Contains(p, ".github"):
		return "CI/CD pipeline"
	case strings.Contains(p, "dockerfile") || strings.Contains(p, "compose"):
		return "Container build/runtime config"
	case strings.HasSuffix(p, ".tf") || strings.Contains(content, "resource \"") && strings.Contains(content, "terraform"):
		return "Infrastructure as Code"
	case strings.HasSuffix(p, ".yml") || strings.HasSuffix(p, ".yaml"):
		if strings.Contains(content, "kind: Deployment") || strings.Contains(content, "apiVersion:") {
			return "Kubernetes manifest"
		}
		return "YAML configuration"
	case strings.HasSuffix(p, ".json"):
		return "JSON configuration"
	case strings.HasSuffix(p, ".go") || strings.HasSuffix(p, ".py") || strings.HasSuffix(p, ".js") || strings.HasSuffix(p, ".ts"):
		if regexp.MustCompile(`(?i)(pii|personal data|gdpr|rgpd)`).MatchString(content) {
			return "Code references to PII/GDPR"
		}
		return "Application source code"
	default:
		return ""
	}
}

func sampleSnippet(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	head := truncate(s, n/2)
	tail := lastN(s, n/2)
	return head + "\n...\n" + tail
}

func safeExcerpt(s string, perFile int) string {
	if len(s) <= perFile {
		return s
	}
	// take head and tail chunks
	head := truncate(s, perFile/2)
	tail := lastN(s, perFile/2)
	return head + "\n...\n" + tail
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func lastN(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}

func capReached(excerpts []string, capBytes int) bool {
	var total int
	for _, e := range excerpts {
		total += len(e)
	}
	return total >= capBytes
}

func buildPrompt(col *Collected) string {
	var b strings.Builder
	b.WriteString(systemPrompt)
	b.WriteString("\n\nCOLLECTED_EVIDENCE:\n")
	meta := struct {
		FilesScanned int         `json:"files_scanned"`
		Findings     []Finding   `json:"findings"`
		Secrets      []SecretHit `json:"secrets"`
	}{
		FilesScanned: col.FilesScanned,
		Findings:     col.Findings,
		Secrets:      col.Secrets,
	}
	j, _ := json.Marshal(meta)
	b.Write(j)
	b.WriteString("\n\nSNIPPETS:\n")
	b.WriteString(col.ExcerptPack)
	b.WriteString("\n\nTASK: First output STRICT JSON only (no markdown). Then a short plain-text summary prefixed by 'SUMMARY:'.")
	return b.String()
}

func callAzureChat(ctx context.Context, endpoint, deployment, apiVersion, apiKey, prompt string, maxTokens int) (string, error) {
	url := fmt.Sprintf("%s/openai/deployments/%s/chat/completions?api-version=%s", strings.TrimRight(endpoint, "/"), deployment, apiVersion)

	reqBody := LLMRequest{
		Messages: []LLMMessage{
			{Role: "system", Content: "You are an accurate, terse compliance assistant."},
			{Role: "user", Content: prompt},
		},
		Temperature: 0.1,
		TopP:        0.95,
		MaxTokens:   maxTokens,
	}
	body, _ := json.Marshal(reqBody)

	req, _ := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("api-key", apiKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("azure api error: %s\n%s", resp.Status, string(b))
	}

	var parsed LLMResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return "", err
	}
	if len(parsed.Choices) == 0 {
		return "", errors.New("empty LLM response")
	}
	return parsed.Choices[0].Message.Content, nil
}

func splitJsonAndSummary(s string) (jsonPart, summary string) {
	// Expect JSON first, then "SUMMARY:"
	idx := strings.Index(s, "SUMMARY:")
	if idx == -1 {
		return s, ""
	}
	return strings.TrimSpace(s[:idx]), strings.TrimSpace(s[idx+len("SUMMARY:"):])
}

func getenvDefault(k, def string) string {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	return v
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "Erreur: %v\n", err)
	os.Exit(1)
}
