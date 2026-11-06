// ODedupe — Duplicate File Hunter
// Part of the OWL security suite.  Author: khaled.s.haddad   Site: owlsec.org
// Language: Go (stdlib only, CGO disabled, static single-file build).
//
// ODedupe is a professional, offline-first Duplicate File Hunter with an interactive cyan owl
// TUI and a full CLI (flag-based) supporting txt|md|json|csv|sarif exports, MITRE
// ATT&CK tagging on findings where meaningful, and A+..F posture grading.

package main

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	APPNAME = "ODedupe"
	SUITE   = "Owl Dedupe Suite"
	TAGLINE = "Duplicate File Hunter"
	SUBLINE = "Scan · Verify · Fuzzy · Hardlink-aware · Plan · Baseline · Grade"
	VERSION = "1.0"
	AUTHOR  = "khaled.s.haddad"
	WEBSITE = "owlsec.org"
)

const BANNER = `
 ██████╗ ██████╗ ███████╗██████╗ ██╗   ██╗██████╗ ███████╗
██╔═══██╗██╔══██╗██╔════╝██╔══██╗██║   ██║██╔══██╗██╔════╝
██║   ██║██║  ██║█████╗  ██║  ██║██║   ██║██████╔╝█████╗
██║   ██║██║  ██║██╔══╝  ██║  ██║██║   ██║██╔═══╝ ██╔══╝
╚██████╔╝██████╔╝███████╗██████╔╝╚██████╔╝██║     ███████╗
 ╚═════╝ ╚═════╝ ╚══════╝╚═════╝  ╚═════╝ ╚═╝     ╚══════╝
`

// ---- OWL UI KIT (cyan "owl" house style) — stdlib only. Shared across the suite ----
// CYAN is the primary brand/frame colour; red is reserved for errors and
// CRITICAL/HIGH severities.
const (
	R   = "\033[91m"       // red     — errors / critical
	GRN = "\033[92m"       // green   — success / low
	YLW = "\033[93m"       // yellow  — prompts / warning text
	CY  = "\033[96m"       // cyan    — primary brand & frames
	W   = "\033[97m"       // white   — body text
	B   = "\033[1m"        // bold
	X   = "\033[0m"        // reset
	MG  = "\033[95m"       // magenta — suite name / accents
	BL  = "\033[94m"       // blue    — accents
	DIM = "\033[2m"        // dim     — secondary text
	OR  = "\033[38;5;208m" // orange  — warning markers
	GY  = "\033[90m"       // gray    — muted
	DR  = CY               // legacy alias: former frame colour → cyan
)

var noColor = os.Getenv("NO_COLOR") != "" || !isatty()

func isatty() bool { fi, _ := os.Stdout.Stat(); return (fi.Mode() & os.ModeCharDevice) != 0 }
func col(s string, c ...string) string {
	if noColor {
		return s
	}
	return strings.Join(c, "") + s + X
}
func clear()           { fmt.Print("\033[H\033[2J") }
func line(w int)       { fmt.Println(col(strings.Repeat("─", w), CY)) }
func okMsg(s string)   { fmt.Println("  " + col("[✔] ", GRN+B) + col(s, W)) }
func errMsg(s string)  { fmt.Println("  " + col("[✘] ", R+B) + col(s, R)) }
func warnMsg(s string) { fmt.Println("  " + col("[!] ", OR+B) + col(s, YLW)) }
func info(s string)    { fmt.Println("  " + col("[*] ", CY) + col(s, DIM+W)) }

// banner prints the cyan ANSI-Shadow wordmark and the suite identity block.
func banner() {
	fmt.Println(col(BANNER, CY))
	fmt.Println("  " + col(SUITE+"  ", B+MG) + col("v"+VERSION, YLW))
	fmt.Println("  " + col(SUBLINE, W))
	fmt.Println()
	fmt.Println("  " + col("Developer : ", DIM) + col(AUTHOR, CY) +
		col("   |   Website : ", DIM) + col(WEBSITE, CY))
	fmt.Println(col(strings.Repeat("─", 66), CY))
	fmt.Println()
}
func prompt(label string) string {
	fmt.Print("  " + col("[»] ", YLW) + col(label+": ", W))
	rd := bufio.NewReader(os.Stdin)
	s, err := rd.ReadString('\n')
	if err != nil && s == "" {
		fmt.Println()
		os.Exit(0) // stdin closed (Ctrl-D / end of piped input)
	}
	return strings.TrimSpace(s)
}
func pause() {
	fmt.Print(col("\n  [↩] Press Enter to continue...", YLW))
	bufio.NewReader(os.Stdin).ReadString('\n')
}

// sectionHeader prints a ⬡ heading between two cyan rules.
func sectionHeader(s string) {
	fmt.Println(col(strings.Repeat("─", 66), CY))
	fmt.Println("  " + col("⬡  "+s, B+CY))
	fmt.Println(col(strings.Repeat("─", 66), CY))
	fmt.Println()
}

type menuItem struct {
	key, name, desc, clr string
}

// menu renders the ONode-style main menu and returns the raw selection.
func menu(title string, items []menuItem) string {
	clear()
	banner()
	fmt.Println("  " + col("⬡  "+title, B+CY))
	fmt.Println()
	for _, it := range items {
		fmt.Println("  " + col(pad("["+it.key+"]", 4), it.clr) + "  " +
			col(pad(it.name, 32), W) + col("─ "+it.desc, DIM))
	}
	fmt.Println()
	fmt.Println("  " + col(pad("[H]", 4), YLW+B) + "  " + col(pad("Help & Usage", 32), W) + col("─ How to use, every option, CLI flags & examples", DIM))
	fmt.Println("  " + col(pad("[0]", 4), R) + "  " + col(pad("Exit", 32), W) + col("─ Quit "+APPNAME, DIM))
	fmt.Println()
	fmt.Println(col(strings.Repeat("─", 66), CY))
	return prompt("Select option")
}
func pad(s string, n int) string {
	if visw(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-visw(s))
}
func visw(s string) int { return len([]rune(s)) }
func table(headers []string, rows [][]string) {
	w := make([]int, len(headers))
	for i, h := range headers {
		w[i] = visw(h)
	}
	for _, r := range rows {
		for i, c := range r {
			if i < len(w) && visw(c) > w[i] {
				w[i] = visw(c)
			}
		}
	}
	var hb strings.Builder
	for i, h := range headers {
		hb.WriteString(col(pad(h, w[i]), CY+B))
		if i < len(headers)-1 {
			hb.WriteString(col(" \u2502 ", DR))
		}
	}
	fmt.Println("  " + hb.String())
	seg := make([]string, len(w))
	for i := range w {
		seg[i] = strings.Repeat("\u2500", w[i])
	}
	fmt.Println("  " + col(strings.Join(seg, "\u2500\u253c\u2500"), DR))
	for _, r := range rows {
		var rb strings.Builder
		for i := range headers {
			v := ""
			if i < len(r) {
				v = r[i]
			}
			rb.WriteString(col(pad(v, w[i]), W))
			if i < len(headers)-1 {
				rb.WriteString(col(" \u2502 ", DR))
			}
		}
		fmt.Println("  " + rb.String())
	}
}

// ---- shared finding model, grading, and 5-format export engine ----
type Finding struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Severity    string   `json:"severity"`
	Category    string   `json:"category"`
	ATTCK       []string `json:"attck,omitempty"`
	CWE         string   `json:"cwe,omitempty"`
	Description string   `json:"description"`
	Evidence    string   `json:"evidence,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
	Location    string   `json:"location,omitempty"`
	Score       float64  `json:"score"`
}

type KV struct {
	K string `json:"key"`
	V string `json:"value"`
}

type Report struct {
	Tool      string    `json:"tool"`
	Tagline   string    `json:"tagline"`
	Version   string    `json:"version"`
	Target    string    `json:"target"`
	Generated string    `json:"generated"`
	Findings  []Finding `json:"findings"`
	Stats     []KV      `json:"stats"`
	Notes     []string  `json:"notes,omitempty"`
	Grade     string    `json:"grade"`
	Score     float64   `json:"score"`
}

var sevOrder = map[string]int{"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}

func sevRank(s string) int {
	if v, ok := sevOrder[strings.ToUpper(s)]; ok {
		return v
	}
	return 0
}
func sevColor(s string) string {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return R + B
	case "HIGH":
		return R
	case "MEDIUM":
		return YLW
	case "LOW":
		return GRN
	default:
		return GY
	}
}
func sortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		if sevRank(fs[i].Severity) != sevRank(fs[j].Severity) {
			return sevRank(fs[i].Severity) > sevRank(fs[j].Severity)
		}
		return fs[i].Score > fs[j].Score
	})
}
func gradeFromScore(f float64) string {
	switch {
	case f >= 97:
		return "A+"
	case f >= 93:
		return "A"
	case f >= 90:
		return "A-"
	case f >= 87:
		return "B+"
	case f >= 83:
		return "B"
	case f >= 80:
		return "B-"
	case f >= 77:
		return "C+"
	case f >= 73:
		return "C"
	case f >= 70:
		return "C-"
	case f >= 65:
		return "D+"
	case f >= 60:
		return "D"
	default:
		return "F"
	}
}
func computePosture(fs []Finding) (string, float64) {
	score := 100.0
	for _, f := range fs {
		switch strings.ToUpper(f.Severity) {
		case "CRITICAL":
			score -= 22
		case "HIGH":
			score -= 13
		case "MEDIUM":
			score -= 6
		case "LOW":
			score -= 2.5
		case "INFO":
			score -= 0.3
		}
	}
	if score < 0 {
		score = 0
	}
	return gradeFromScore(score), score
}
func sevCounts(fs []Finding) map[string]int {
	m := map[string]int{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
	for _, f := range fs {
		m[strings.ToUpper(f.Severity)]++
	}
	return m
}
func newReport(target string) *Report {
	g, s := "", 0.0
	_ = g
	_ = s
	return &Report{
		Tool:      APPNAME,
		Tagline:   TAGLINE,
		Version:   VERSION,
		Target:    target,
		Generated: time.Now().Format("2006-01-02 15:04:05 -0700"),
	}
}
func (r *Report) finalize() {
	sortFindings(r.Findings)
	r.Grade, r.Score = computePosture(r.Findings)
}

func jsonEscape(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func exportJSON(r *Report) string {
	r.finalize()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	_ = enc.Encode(r)
	return buf.String()
}

func exportCSV(r *Report) string {
	r.finalize()
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	w.Write([]string{"id", "severity", "score", "category", "title", "attck", "cwe", "location", "description", "remediation"})
	for _, f := range r.Findings {
		w.Write([]string{f.ID, f.Severity, strconv.FormatFloat(f.Score, 'f', 1, 64), f.Category, f.Title, strings.Join(f.ATTCK, " "), f.CWE, f.Location, oneLine(f.Description), oneLine(f.Remediation)})
	}
	w.Flush()
	return buf.String()
}

func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	return strings.TrimSpace(s)
}

func exportTXT(r *Report) string {
	r.finalize()
	var b strings.Builder
	bar := strings.Repeat("=", 72)
	b.WriteString(bar + "\n")
	b.WriteString("  " + r.Tool + " — " + r.Tagline + "\n")
	b.WriteString("  Author: khaled.s.haddad    Site: owlsec.org    Version: " + r.Version + "\n")
	b.WriteString(bar + "\n")
	b.WriteString("Target    : " + r.Target + "\n")
	b.WriteString("Generated : " + r.Generated + "\n")
	b.WriteString(fmt.Sprintf("Posture   : %s (%.1f/100)\n", r.Grade, r.Score))
	c := sevCounts(r.Findings)
	b.WriteString(fmt.Sprintf("Findings  : %d  [CRIT %d | HIGH %d | MED %d | LOW %d | INFO %d]\n",
		len(r.Findings), c["CRITICAL"], c["HIGH"], c["MEDIUM"], c["LOW"], c["INFO"]))
	if len(r.Stats) > 0 {
		b.WriteString("\n-- Statistics --\n")
		for _, kv := range r.Stats {
			b.WriteString(fmt.Sprintf("  %-28s : %s\n", kv.K, kv.V))
		}
	}
	if len(r.Findings) > 0 {
		b.WriteString("\n-- Findings --\n")
		for i, f := range r.Findings {
			b.WriteString(fmt.Sprintf("\n[%d] %s  (%s, score %.1f)\n", i+1, f.Title, f.Severity, f.Score))
			b.WriteString("    id         : " + f.ID + "\n")
			b.WriteString("    category   : " + f.Category + "\n")
			if len(f.ATTCK) > 0 {
				b.WriteString("    att&ck     : " + annotateATTCK(f.ATTCK) + "\n")
			}
			if f.CWE != "" {
				b.WriteString("    cwe        : " + f.CWE + "\n")
			}
			if f.Location != "" {
				b.WriteString("    location   : " + f.Location + "\n")
			}
			if f.Description != "" {
				b.WriteString("    detail     : " + f.Description + "\n")
			}
			if f.Evidence != "" {
				b.WriteString("    evidence   : " + oneLine(f.Evidence) + "\n")
			}
			if f.Remediation != "" {
				b.WriteString("    fix        : " + f.Remediation + "\n")
			}
		}
	}
	if len(r.Notes) > 0 {
		b.WriteString("\n-- Notes --\n")
		for _, n := range r.Notes {
			b.WriteString("  * " + n + "\n")
		}
	}
	b.WriteString("\n" + bar + "\n")
	return b.String()
}

func exportMD(r *Report) string {
	r.finalize()
	var b strings.Builder
	b.WriteString("# " + r.Tool + " Report\n\n")
	b.WriteString("*" + r.Tagline + "*\n\n")
	b.WriteString("| Field | Value |\n|---|---|\n")
	b.WriteString("| Target | " + mdEsc(r.Target) + " |\n")
	b.WriteString("| Generated | " + r.Generated + " |\n")
	b.WriteString("| Version | " + r.Version + " |\n")
	b.WriteString(fmt.Sprintf("| Posture | **%s** (%.1f/100) |\n", r.Grade, r.Score))
	c := sevCounts(r.Findings)
	b.WriteString(fmt.Sprintf("| Findings | %d (C%d/H%d/M%d/L%d/I%d) |\n\n",
		len(r.Findings), c["CRITICAL"], c["HIGH"], c["MEDIUM"], c["LOW"], c["INFO"]))
	if len(r.Stats) > 0 {
		b.WriteString("## Statistics\n\n| Metric | Value |\n|---|---|\n")
		for _, kv := range r.Stats {
			b.WriteString("| " + mdEsc(kv.K) + " | " + mdEsc(kv.V) + " |\n")
		}
		b.WriteString("\n")
	}
	if len(r.Findings) > 0 {
		b.WriteString("## Findings\n\n")
		for i, f := range r.Findings {
			b.WriteString(fmt.Sprintf("### %d. %s\n\n", i+1, mdEsc(f.Title)))
			b.WriteString("- **Severity:** " + f.Severity + fmt.Sprintf(" (score %.1f)\n", f.Score))
			b.WriteString("- **ID:** `" + f.ID + "`\n")
			b.WriteString("- **Category:** " + mdEsc(f.Category) + "\n")
			if len(f.ATTCK) > 0 {
				b.WriteString("- **ATT&CK:** " + annotateATTCK(f.ATTCK) + "\n")
			}
			if f.CWE != "" {
				b.WriteString("- **CWE:** " + f.CWE + "\n")
			}
			if f.Location != "" {
				b.WriteString("- **Location:** `" + f.Location + "`\n")
			}
			if f.Description != "" {
				b.WriteString("- **Detail:** " + mdEsc(f.Description) + "\n")
			}
			if f.Evidence != "" {
				b.WriteString("- **Evidence:** `" + oneLine(f.Evidence) + "`\n")
			}
			if f.Remediation != "" {
				b.WriteString("- **Fix:** " + mdEsc(f.Remediation) + "\n")
			}
			b.WriteString("\n")
		}
	}
	if len(r.Notes) > 0 {
		b.WriteString("## Notes\n\n")
		for _, n := range r.Notes {
			b.WriteString("- " + mdEsc(n) + "\n")
		}
	}
	return b.String()
}

func mdEsc(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	return s
}

func sarifLevel(sev string) string {
	switch strings.ToUpper(sev) {
	case "CRITICAL", "HIGH":
		return "error"
	case "MEDIUM":
		return "warning"
	case "LOW", "INFO":
		return "note"
	default:
		return "none"
	}
}

func exportSARIF(r *Report) string {
	r.finalize()
	type sarifMsg struct {
		Text string `json:"text"`
	}
	type sarifRule struct {
		ID               string            `json:"id"`
		Name             string            `json:"name"`
		ShortDescription sarifMsg          `json:"shortDescription"`
		FullDescription  sarifMsg          `json:"fullDescription"`
		HelpURI          string            `json:"helpUri,omitempty"`
		Properties       map[string]any    `json:"properties,omitempty"`
		DefaultConfig    map[string]string `json:"defaultConfiguration,omitempty"`
	}
	type sarifArtifact struct {
		URI string `json:"uri"`
	}
	type sarifRegion struct {
		StartLine int `json:"startLine,omitempty"`
	}
	type sarifPhys struct {
		ArtifactLocation sarifArtifact `json:"artifactLocation"`
		Region           *sarifRegion  `json:"region,omitempty"`
	}
	type sarifLoc struct {
		PhysicalLocation sarifPhys `json:"physicalLocation"`
	}
	type sarifResult struct {
		RuleID    string         `json:"ruleId"`
		Level     string         `json:"level"`
		Message   sarifMsg       `json:"message"`
		Locations []sarifLoc     `json:"locations,omitempty"`
		Props     map[string]any `json:"properties,omitempty"`
	}
	type sarifDriver struct {
		Name           string      `json:"name"`
		Version        string      `json:"version"`
		InformationURI string      `json:"informationUri"`
		Rules          []sarifRule `json:"rules"`
	}
	type sarifTool struct {
		Driver sarifDriver `json:"driver"`
	}
	type sarifRun struct {
		Tool    sarifTool     `json:"tool"`
		Results []sarifResult `json:"results"`
	}
	type sarifDoc struct {
		Schema  string     `json:"$schema"`
		Version string     `json:"version"`
		Runs    []sarifRun `json:"runs"`
	}
	ruleSeen := map[string]bool{}
	var rules []sarifRule
	var results []sarifResult
	for _, f := range r.Findings {
		if !ruleSeen[f.ID] {
			ruleSeen[f.ID] = true
			props := map[string]any{"severity": f.Severity, "category": f.Category}
			if len(f.ATTCK) > 0 {
				props["attck"] = f.ATTCK
			}
			if f.CWE != "" {
				props["cwe"] = f.CWE
			}
			rules = append(rules, sarifRule{
				ID:               f.ID,
				Name:             f.Title,
				ShortDescription: sarifMsg{Text: f.Title},
				FullDescription:  sarifMsg{Text: nonEmpty(f.Description, f.Title)},
				HelpURI:          "https://owlsec.org",
				Properties:       props,
				DefaultConfig:    map[string]string{"level": sarifLevel(f.Severity)},
			})
		}
		loc := nonEmpty(f.Location, r.Target)
		res := sarifResult{
			RuleID:  f.ID,
			Level:   sarifLevel(f.Severity),
			Message: sarifMsg{Text: nonEmpty(f.Description, f.Title)},
			Props:   map[string]any{"score": f.Score, "severity": f.Severity},
			Locations: []sarifLoc{{PhysicalLocation: sarifPhys{
				ArtifactLocation: sarifArtifact{URI: loc},
			}}},
		}
		results = append(results, res)
	}
	doc := sarifDoc{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           r.Tool,
				Version:        r.Version,
				InformationURI: "https://owlsec.org",
				Rules:          rules,
			}},
			Results: results,
		}},
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	_ = enc.Encode(doc)
	return buf.String()
}

func nonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

func renderReport(r *Report, format string) string {
	switch strings.ToLower(format) {
	case "json":
		return exportJSON(r)
	case "csv":
		return exportCSV(r)
	case "md", "markdown":
		return exportMD(r)
	case "sarif":
		return exportSARIF(r)
	default:
		return exportTXT(r)
	}
}

func emit(r *Report, format, output string) error {
	content := renderReport(r, format)
	if output == "" || output == "-" {
		fmt.Print(content)
		if !strings.HasSuffix(content, "\n") {
			fmt.Println()
		}
		return nil
	}
	if err := os.WriteFile(output, []byte(content), 0644); err != nil {
		return err
	}
	okMsg("wrote " + format + " report to " + output)
	return nil
}

func showFindingsTUI(r *Report) {
	r.finalize()
	if len(r.Findings) == 0 {
		okMsg("no findings")
		return
	}
	rows := [][]string{}
	for _, f := range r.Findings {
		at := strings.Join(f.ATTCK, ",")
		if at == "" {
			at = "-"
		}
		rows = append(rows, []string{f.ID, f.Severity, fmt.Sprintf("%.1f", f.Score), f.Title, at})
	}
	table([]string{"ID", "SEV", "SCORE", "TITLE", "ATT&CK"}, rows)
	fmt.Println()
	info(fmt.Sprintf("posture grade %s (%.1f/100)", r.Grade, r.Score))
}

// ---- shared utility helpers (hexdump, entropy, histograms, formatting) ----
func hexDump(b []byte) string {
	var sb strings.Builder
	for i := 0; i < len(b); i += 16 {
		sb.WriteString(fmt.Sprintf("%08x  ", i))
		for j := 0; j < 16; j++ {
			if i+j < len(b) {
				sb.WriteString(fmt.Sprintf("%02x ", b[i+j]))
			} else {
				sb.WriteString("   ")
			}
			if j == 7 {
				sb.WriteString(" ")
			}
		}
		sb.WriteString(" |")
		for j := 0; j < 16 && i+j < len(b); j++ {
			c := b[i+j]
			if c >= 32 && c < 127 {
				sb.WriteByte(c)
			} else {
				sb.WriteByte('.')
			}
		}
		sb.WriteString("|\n")
	}
	return sb.String()
}

func entropyOf(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var freq [256]int
	for _, c := range b {
		freq[c]++
	}
	var h float64
	n := float64(len(b))
	for _, f := range freq {
		if f == 0 {
			continue
		}
		p := float64(f) / n
		h -= p * mathLog2(p)
	}
	return h
}

func mathLog2(x float64) float64 { return lnApprox(x) / 0.6931471805599453 }

func lnApprox(x float64) float64 {
	if x <= 0 {
		return 0
	}
	k := 0
	for x > 2 {
		x /= 2
		k++
	}
	for x < 0.5 {
		x *= 2
		k--
	}
	y := (x - 1) / (x + 1)
	y2 := y * y
	sum := 0.0
	term := y
	for i := 1; i <= 19; i += 2 {
		sum += term / float64(i)
		term *= y2
	}
	return 2*sum + float64(k)*0.6931471805599453
}

func humanBytes(n int64) string {
	const u = 1024
	if n < u {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(u), 0
	for x := n / u; x >= u; x /= u {
		div *= u
		exp++
	}
	units := []string{"KB", "MB", "GB", "TB", "PB", "EB"}
	return fmt.Sprintf("%.2f %s", float64(n)/float64(div), units[exp])
}

func commaInt(n int64) string {
	s := strconv.FormatInt(n, 10)
	neg := strings.HasPrefix(s, "-")
	if neg {
		s = s[1:]
	}
	var out []byte
	for i, c := range []byte(s) {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, c)
	}
	if neg {
		return "-" + string(out)
	}
	return string(out)
}

func asciiBar(frac float64, width int) string {
	if frac < 0 {
		frac = 0
	}
	if frac > 1 {
		frac = 1
	}
	fill := int(frac * float64(width))
	if fill > width {
		fill = width
	}
	return strings.Repeat("\u2588", fill) + strings.Repeat("\u2591", width-fill)
}

func byteHistogram(b []byte) [256]int {
	var h [256]int
	for _, c := range b {
		h[c]++
	}
	return h
}

func truncStr(s string, n int) string {
	if len([]rune(s)) <= n {
		return s
	}
	r := []rune(s)
	if n < 1 {
		return ""
	}
	return string(r[:n-1]) + "\u2026"
}

func minI(a, b int) int {
	if a < b {
		return a
	}
	return b
}
func maxI(a, b int) int {
	if a > b {
		return a
	}
	return b
}
func absI(a int) int {
	if a < 0 {
		return -a
	}
	return a
}
func clampF(x, lo, hi float64) float64 {
	if x < lo {
		return lo
	}
	if x > hi {
		return hi
	}
	return x
}

func kvTable(pairs []KV) {
	rows := [][]string{}
	for _, kv := range pairs {
		rows = append(rows, []string{kv.K, kv.V})
	}
	table([]string{"METRIC", "VALUE"}, rows)
}

func printHelpSection(title string, lines []string) {
	fmt.Println(col("  "+title, CY+B))
	for _, l := range lines {
		fmt.Println("    " + l)
	}
	fmt.Println()
}

func readLines(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, l := range strings.Split(string(data), "\n") {
		out = append(out, l)
	}
	return out, nil
}

func wrapText(s string, width int) []string {
	words := strings.Fields(s)
	var lines []string
	cur := ""
	for _, w := range words {
		if len(cur)+len(w)+1 > width {
			lines = append(lines, cur)
			cur = w
		} else if cur == "" {
			cur = w
		} else {
			cur += " " + w
		}
	}
	if cur != "" {
		lines = append(lines, cur)
	}
	return lines
}

// atoiSafe parses an int, returning def on error.
func atoiSafe(s string, def int) int {
	s = strings.TrimSpace(s)
	if v, err := strconv.Atoi(s); err == nil {
		return v
	}
	return def
}

// splitCSVLine does minimal CSV field splitting on a single line.
func splitCSVLine(s string) []string {
	var out []string
	var cur strings.Builder
	inq := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"':
			inq = !inq
		case c == ',' && !inq:
			out = append(out, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(c)
		}
	}
	out = append(out, cur.String())
	return out
}

// ---- shared MITRE ATT&CK + CWE reference (used by finding renderers) ----
var attckNames = map[string]string{
	"T1003":     "OS Credential Dumping",
	"T1003.001": "LSASS Memory",
	"T1005":     "Data from Local System",
	"T1016":     "System Network Configuration Discovery",
	"T1018":     "Remote System Discovery",
	"T1021":     "Remote Services",
	"T1021.001": "Remote Desktop Protocol",
	"T1021.002": "SMB/Windows Admin Shares",
	"T1033":     "System Owner/User Discovery",
	"T1036":     "Masquerading",
	"T1040":     "Network Sniffing",
	"T1046":     "Network Service Discovery",
	"T1048":     "Exfiltration Over Alternative Protocol",
	"T1055":     "Process Injection",
	"T1057":     "Process Discovery",
	"T1059":     "Command and Scripting Interpreter",
	"T1068":     "Exploitation for Privilege Escalation",
	"T1070":     "Indicator Removal",
	"T1070.002": "Clear Linux or Mac System Logs",
	"T1071":     "Application Layer Protocol",
	"T1071.001": "Web Protocols",
	"T1071.004": "DNS",
	"T1078":     "Valid Accounts",
	"T1082":     "System Information Discovery",
	"T1083":     "File and Directory Discovery",
	"T1090":     "Proxy",
	"T1095":     "Non-Application Layer Protocol",
	"T1098":     "Account Manipulation",
	"T1110":     "Brute Force",
	"T1110.001": "Password Guessing",
	"T1110.003": "Password Spraying",
	"T1133":     "External Remote Services",
	"T1135":     "Network Share Discovery",
	"T1136":     "Create Account",
	"T1190":     "Exploit Public-Facing Application",
	"T1203":     "Exploitation for Client Execution",
	"T1210":     "Exploitation of Remote Services",
	"T1211":     "Exploitation for Defense Evasion",
	"T1217":     "Browser Information Discovery",
	"T1222":     "File and Directory Permissions Modification",
	"T1222.001": "Windows File and Directory Permissions Modification",
	"T1222.002": "Linux and Mac File and Directory Permissions Modification",
	"T1480":     "Execution Guardrails",
	"T1485":     "Data Destruction",
	"T1486":     "Data Encrypted for Impact",
	"T1489":     "Service Stop",
	"T1498":     "Network Denial of Service",
	"T1499":     "Endpoint Denial of Service",
	"T1518":     "Software Discovery",
	"T1543":     "Create or Modify System Process",
	"T1543.002": "Systemd Service",
	"T1547":     "Boot or Logon Autostart Execution",
	"T1548":     "Abuse Elevation Control Mechanism",
	"T1548.001": "Setuid and Setgid",
	"T1552":     "Unsecured Credentials",
	"T1552.001": "Credentials In Files",
	"T1552.004": "Private Keys",
	"T1553":     "Subvert Trust Controls",
	"T1557":     "Adversary-in-the-Middle",
	"T1557.001": "LLMNR/NBT-NS Poisoning and SMB Relay",
	"T1562":     "Impair Defenses",
	"T1562.001": "Disable or Modify Tools",
	"T1565":     "Data Manipulation",
	"T1565.001": "Stored Data Manipulation",
	"T1570":     "Lateral Tool Transfer",
	"T1571":     "Non-Standard Port",
	"T1572":     "Protocol Tunneling",
	"T1573":     "Encrypted Channel",
	"T1573.001": "Symmetric Cryptography",
	"T1574":     "Hijack Execution Flow",
	"T1589":     "Gather Victim Identity Information",
	"T1590":     "Gather Victim Network Information",
	"T1595":     "Active Scanning",
	"T1599":     "Network Boundary Bridging",
	"T1600":     "Weaken Encryption",
	"T1602":     "Data from Configuration Repository",
	"T1610":     "Deploy Container",
	"T1611":     "Escape to Host",
}

var cweNames = map[string]string{
	"CWE-22":   "Path Traversal",
	"CWE-78":   "OS Command Injection",
	"CWE-79":   "Cross-site Scripting",
	"CWE-89":   "SQL Injection",
	"CWE-200":  "Exposure of Sensitive Information",
	"CWE-209":  "Information Exposure Through an Error Message",
	"CWE-250":  "Execution with Unnecessary Privileges",
	"CWE-269":  "Improper Privilege Management",
	"CWE-276":  "Incorrect Default Permissions",
	"CWE-295":  "Improper Certificate Validation",
	"CWE-306":  "Missing Authentication for Critical Function",
	"CWE-307":  "Improper Restriction of Excessive Authentication Attempts",
	"CWE-311":  "Missing Encryption of Sensitive Data",
	"CWE-312":  "Cleartext Storage of Sensitive Information",
	"CWE-319":  "Cleartext Transmission of Sensitive Information",
	"CWE-326":  "Inadequate Encryption Strength",
	"CWE-327":  "Use of a Broken or Risky Cryptographic Algorithm",
	"CWE-328":  "Use of Weak Hash",
	"CWE-330":  "Use of Insufficiently Random Values",
	"CWE-338":  "Use of Cryptographically Weak PRNG",
	"CWE-521":  "Weak Password Requirements",
	"CWE-522":  "Insufficiently Protected Credentials",
	"CWE-532":  "Insertion of Sensitive Information into Log File",
	"CWE-601":  "Open Redirect",
	"CWE-732":  "Incorrect Permission Assignment for Critical Resource",
	"CWE-798":  "Use of Hard-coded Credentials",
	"CWE-918":  "Server-Side Request Forgery",
	"CWE-1104": "Use of Unmaintained Third Party Components",
}

func attckName(id string) string {
	if n, ok := attckNames[id]; ok {
		return n
	}
	return id
}

func cweName(id string) string {
	if !strings.HasPrefix(id, "CWE-") {
		id = "CWE-" + id
	}
	if n, ok := cweNames[id]; ok {
		return id + " (" + n + ")"
	}
	return id
}

func annotateATTCK(ids []string) string {
	parts := make([]string, 0, len(ids))
	for _, id := range ids {
		if n := attckName(id); n != id {
			parts = append(parts, id+" "+n)
		} else {
			parts = append(parts, id)
		}
	}
	return strings.Join(parts, ", ")
}

// printTechniqueCatalog lists all known ATT&CK techniques referenced by the suite.
func printTechniqueCatalog() {
	var ids []string
	for id := range attckNames {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	rows := [][]string{}
	for _, id := range ids {
		rows = append(rows, []string{id, attckNames[id]})
	}
	table([]string{"TECHNIQUE", "NAME"}, rows)
}

// ============================================================================
//  ODedupe domain engine — content-addressed duplicate file hunter.
//  Strategy: group by size -> cheap head-hash -> full content hash, in parallel.
//  Produces de-duplication action plans (keep/delete/hardlink/move) plus a
//  wasted-space posture grade. Read-only by default; never mutates the FS.
// ============================================================================

type fileRec struct {
	path    string
	size    int64
	mode    os.FileMode
	modTime time.Time
	headSum string
	fullSum string
	group   int
	dev     uint64 // device + inode identify the on-disk file; two paths with
	ino     uint64 // the same pair are hardlinks (or a symlink and its target)
	hasIno  bool
}

// sameInode reports whether two records are the same on-disk file.
func sameInode(a, b *fileRec) bool {
	return a.hasIno && b.hasIno && a.dev == b.dev && a.ino == b.ino
}

type dupGroup struct {
	hash   string
	size   int64
	files  []*fileRec
	wasted int64
}

type scanConfig struct {
	root        string
	minSize     int64
	maxSize     int64
	algo        string
	followLinks bool
	includeHid  bool
	workers     int
	exts        []string
	namePat     string
	excludes    []string // glob patterns matched against file and directory names
	prefer      string   // keeper preference: a path prefix that should win
}

func defaultConfig(root string) scanConfig {
	return scanConfig{root: root, minSize: 1, maxSize: 0, algo: "sha256", workers: 8}
}

// ---------------------------------------------------------------------------
// Hashing
// ---------------------------------------------------------------------------

func newHasher(algo string) func([]byte) string {
	switch strings.ToLower(algo) {
	case "md5":
		return func(b []byte) string { s := md5.Sum(b); return hex.EncodeToString(s[:]) }
	case "sha1":
		return func(b []byte) string { s := sha1.Sum(b); return hex.EncodeToString(s[:]) }
	default:
		return func(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
	}
}

func hashFileFull(path, algo string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	var h io.Writer
	switch strings.ToLower(algo) {
	case "md5":
		m := md5.New()
		if _, err := io.Copy(m, f); err != nil {
			return "", err
		}
		return hex.EncodeToString(m.Sum(nil)), nil
	case "sha1":
		m := sha1.New()
		if _, err := io.Copy(m, f); err != nil {
			return "", err
		}
		return hex.EncodeToString(m.Sum(nil)), nil
	default:
		m := sha256.New()
		if _, err := io.Copy(m, f); err != nil {
			return "", err
		}
		_ = h
		return hex.EncodeToString(m.Sum(nil)), nil
	}
}

const headBytes = 4096

func hashFileHead(path, algo string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	buf := make([]byte, headBytes)
	// io.ReadFull: a bare Read may legally return fewer bytes than are
	// available (network/FUSE filesystems), which would split real duplicates.
	n, err := io.ReadFull(f, buf)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return "", err
	}
	return newHasher(algo)(buf[:n]), nil
}

// ---------------------------------------------------------------------------
// Walk + collect
// ---------------------------------------------------------------------------

func collectFiles(cfg scanConfig) ([]*fileRec, []string, error) {
	var recs []*fileRec
	var warns []string
	walkFn := func(path string, d os.DirEntry, err error) error {
		if err != nil {
			warns = append(warns, "access: "+path+": "+err.Error())
			return nil
		}
		name := d.Name()
		if d.IsDir() {
			if path != cfg.root && (excluded(name, cfg.excludes) ||
				(!cfg.includeHid && name != "." && strings.HasPrefix(name, "."))) {
				return filepath.SkipDir
			}
			return nil
		}
		if !cfg.includeHid && strings.HasPrefix(name, ".") {
			return nil
		}
		if excluded(name, cfg.excludes) {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			warns = append(warns, "stat: "+path+": "+err.Error())
			return nil
		}
		if info.Mode()&os.ModeSymlink != 0 {
			if !cfg.followLinks {
				return nil
			}
			// WalkDir reports the link itself (Lstat); resolve it so a link to a
			// regular file is scanned as that file. Links to directories are not
			// descended, which also rules out symlink loops.
			if info, err = os.Stat(path); err != nil {
				warns = append(warns, "symlink: "+path+": "+err.Error())
				return nil
			}
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		sz := info.Size()
		if sz < cfg.minSize {
			return nil
		}
		if cfg.maxSize > 0 && sz > cfg.maxSize {
			return nil
		}
		if len(cfg.exts) > 0 && !matchExt(name, cfg.exts) {
			return nil
		}
		if cfg.namePat != "" && !strings.Contains(strings.ToLower(name), strings.ToLower(cfg.namePat)) {
			return nil
		}
		rec := &fileRec{path: path, size: sz, mode: info.Mode(), modTime: info.ModTime(), group: -1}
		if st, ok := info.Sys().(*syscall.Stat_t); ok {
			rec.dev, rec.ino, rec.hasIno = uint64(st.Dev), uint64(st.Ino), true
		}
		recs = append(recs, rec)
		return nil
	}
	err := filepath.WalkDir(cfg.root, walkFn)
	return recs, warns, err
}

// excluded reports whether a file or directory name matches any --exclude glob.
func excluded(name string, pats []string) bool {
	for _, p := range pats {
		if p == "" {
			continue
		}
		if ok, _ := filepath.Match(p, name); ok {
			return true
		}
	}
	return false
}

func matchExt(name string, exts []string) bool {
	e := strings.ToLower(filepath.Ext(name))
	for _, x := range exts {
		x = strings.ToLower(x)
		if !strings.HasPrefix(x, ".") {
			x = "." + x
		}
		if e == x {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Dedup pipeline
// ---------------------------------------------------------------------------

type scanResult struct {
	cfg        scanConfig
	total      int
	candidates int
	groups     []dupGroup
	totalBytes int64
	wasted     int64
	warnings   []string
	elapsed    time.Duration
	all        []*fileRec // every file that passed the filters (fuzzy scan needs non-duplicates too)
	linked     int        // copies that already share an inode with another copy
}

func runScan(cfg scanConfig) (*scanResult, error) {
	start := time.Now()
	if cfg.workers < 1 {
		cfg.workers = 1
	}
	recs, warns, err := collectFiles(cfg)
	if err != nil {
		return nil, err
	}
	res := &scanResult{cfg: cfg, total: len(recs), warnings: warns, all: recs}
	// stage 1: group by size
	bySize := map[int64][]*fileRec{}
	for _, r := range recs {
		res.totalBytes += r.size
		bySize[r.size] = append(bySize[r.size], r)
	}
	// stage 2: for size-collisions, head-hash, then full-hash in parallel
	var toHash []*fileRec
	for _, grp := range bySize {
		if len(grp) < 2 {
			continue
		}
		toHash = append(toHash, grp...)
	}
	res.candidates = len(toHash)
	res.warnings = append(res.warnings, hashParallel(toHash, cfg, true)...)
	// group by (size, head)
	byHead := map[string][]*fileRec{}
	for _, r := range toHash {
		key := strconv.FormatInt(r.size, 10) + ":" + r.headSum
		byHead[key] = append(byHead[key], r)
	}
	var toFull []*fileRec
	for _, grp := range byHead {
		if len(grp) < 2 {
			continue
		}
		toFull = append(toFull, grp...)
	}
	res.warnings = append(res.warnings, hashParallel(toFull, cfg, false)...)
	byFull := map[string][]*fileRec{}
	for _, r := range toFull {
		if r.fullSum == "" {
			continue
		}
		byFull[r.fullSum] = append(byFull[r.fullSum], r)
	}
	for h, grp := range byFull {
		if len(grp) < 2 {
			continue
		}
		sort.Slice(grp, func(i, j int) bool { return grp[i].modTime.Before(grp[j].modTime) })
		// Waste counts distinct on-disk files beyond the first: hardlinked
		// copies (and symlinks to a copy) share storage and reclaim nothing.
		distinct := distinctInodes(grp)
		wasted := int64(distinct-1) * grp[0].size
		res.linked += len(grp) - distinct
		res.groups = append(res.groups, dupGroup{hash: h, size: grp[0].size, files: grp, wasted: wasted})
		res.wasted += wasted
	}
	sort.Slice(res.groups, func(i, j int) bool {
		if res.groups[i].wasted != res.groups[j].wasted {
			return res.groups[i].wasted > res.groups[j].wasted
		}
		return res.groups[i].hash < res.groups[j].hash
	})
	// Group ids follow the final (sorted) order so they match listings.
	for i, g := range res.groups {
		for _, r := range g.files {
			r.group = i
		}
	}
	res.elapsed = time.Since(start)
	return res, nil
}

// distinctInodes counts the distinct on-disk files among recs; records
// without inode information each count as their own file.
func distinctInodes(recs []*fileRec) int {
	seen := map[[2]uint64]bool{}
	n := 0
	for _, r := range recs {
		if !r.hasIno {
			n++
			continue
		}
		k := [2]uint64{r.dev, r.ino}
		if !seen[k] {
			seen[k] = true
			n++
		}
	}
	return n
}

// hashParallel fills headSum (head=true) or fullSum for recs using cfg.workers
// goroutines and returns one warning per file that could not be read, so
// unreadable files are reported instead of silently dropping out of groups.
func hashParallel(recs []*fileRec, cfg scanConfig, head bool) []string {
	if len(recs) == 0 {
		return nil
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	var warns []string
	ch := make(chan *fileRec, len(recs))
	for _, r := range recs {
		ch <- r
	}
	close(ch)
	for i := 0; i < cfg.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for r := range ch {
				var s string
				var err error
				if head {
					s, err = hashFileHead(r.path, cfg.algo)
				} else {
					s, err = hashFileFull(r.path, cfg.algo)
				}
				if err != nil {
					mu.Lock()
					warns = append(warns, "hash: "+r.path+": "+err.Error())
					mu.Unlock()
					continue
				}
				if head {
					r.headSum = s
				} else {
					r.fullSum = s
				}
			}
		}()
	}
	wg.Wait()
	sort.Strings(warns)
	return warns
}

// ---------------------------------------------------------------------------
// Action plans (never executed by default — this tool is read-only)
// ---------------------------------------------------------------------------

type action struct {
	op     string // KEEP, DELETE, HARDLINK, MOVE
	path   string
	target string
	size   int64
}

type planConfig struct {
	strategy string // keep-oldest, keep-newest, keep-shortest-path
	op       string // delete, hardlink, move
	moveDir  string
	prefer   string // path prefix whose copies are kept first
}

// chooseKeeper picks the copy to keep. A keeper under prefer (if set) always
// wins over one outside it; the strategy breaks ties.
func chooseKeeper(files []*fileRec, strategy string, prefer ...string) int {
	pref := ""
	if len(prefer) > 0 {
		pref = prefer[0]
	}
	under := func(f *fileRec) bool { return pref != "" && strings.HasPrefix(f.path, pref) }
	best := 0
	for i := 1; i < len(files); i++ {
		if under(files[i]) != under(files[best]) {
			if under(files[i]) {
				best = i
			}
			continue
		}
		switch strategy {
		case "keep-newest":
			if files[i].modTime.After(files[best].modTime) {
				best = i
			}
		case "keep-shortest-path":
			if len(files[i].path) < len(files[best].path) {
				best = i
			}
		default: // keep-oldest
			if files[i].modTime.Before(files[best].modTime) {
				best = i
			}
		}
	}
	return best
}

func buildPlan(res *scanResult, pc planConfig) []action {
	var plan []action
	usedDst := map[string]bool{}
	for _, g := range res.groups {
		keep := chooseKeeper(g.files, pc.strategy, pc.prefer)
		keeper := g.files[keep]
		plan = append(plan, action{op: "KEEP", path: keeper.path, size: keeper.size})
		for i, f := range g.files {
			if i == keep {
				continue
			}
			// A copy that already shares the keeper's inode is a hardlink or a
			// symlink to it: touching it reclaims nothing, and deleting the
			// target of a symlink keeper would destroy the only data.
			if sameInode(f, keeper) {
				continue
			}
			switch pc.op {
			case "hardlink":
				plan = append(plan, action{op: "HARDLINK", path: f.path, target: keeper.path, size: f.size})
			case "move":
				// Duplicates very often share a basename across groups; give each
				// destination a unique name so one mv never clobbers another file.
				base := filepath.Base(f.path)
				dst := filepath.Join(pc.moveDir, base)
				for n := 1; usedDst[dst]; n++ {
					ext := filepath.Ext(base)
					dst = filepath.Join(pc.moveDir, fmt.Sprintf("%s.%d%s", strings.TrimSuffix(base, ext), n, ext))
				}
				usedDst[dst] = true
				plan = append(plan, action{op: "MOVE", path: f.path, target: dst, size: f.size})
			default:
				plan = append(plan, action{op: "DELETE", path: f.path, target: keeper.path, size: f.size})
			}
		}
	}
	return plan
}

func reclaimableBytes(plan []action) int64 {
	var n int64
	for _, a := range plan {
		if a.op == "DELETE" || a.op == "HARDLINK" || a.op == "MOVE" {
			n += a.size
		}
	}
	return n
}

// writePlanScript emits a shell script the operator can review and run manually.
// Every destructive line is guarded by `cmp -s keeper copy`, so a file that
// changed after the scan (or a hash collision) is left untouched and reported.
func writePlanScript(plan []action) string {
	var b strings.Builder
	b.WriteString("#!/bin/sh\n# ODedupe action plan — REVIEW before running. Generated read-only.\n")
	b.WriteString("# Each action re-checks byte equality with cmp first; mismatches are skipped.\n")
	b.WriteString("set -u\n")
	b.WriteString("skip() { echo \"SKIPPED (content differs or missing): $1\" >&2; }\n\n")
	keeper := ""
	for _, a := range plan {
		switch a.op {
		case "KEEP":
			keeper = a.path
			b.WriteString("# keep: " + shellQuote(a.path) + "\n")
		case "DELETE":
			b.WriteString("cmp -s -- " + shellQuote(keeper) + " " + shellQuote(a.path) + " && rm -f -- " + shellQuote(a.path) + " || skip " + shellQuote(a.path) + "\n")
		case "HARDLINK":
			b.WriteString("cmp -s -- " + shellQuote(a.target) + " " + shellQuote(a.path) + " && ln -f -- " + shellQuote(a.target) + " " + shellQuote(a.path) + " || skip " + shellQuote(a.path) + "\n")
		case "MOVE":
			b.WriteString("cmp -s -- " + shellQuote(keeper) + " " + shellQuote(a.path) + " && mkdir -p -- " + shellQuote(filepath.Dir(a.target)) + " && mv -n -- " + shellQuote(a.path) + " " + shellQuote(a.target) + " || skip " + shellQuote(a.path) + "\n")
		}
	}
	return b.String()
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'" }

// ---------------------------------------------------------------------------
// Fuzzy / near-duplicate detection (name + size proximity + head similarity)
// ---------------------------------------------------------------------------

type fuzzyPair struct {
	a, b  *fileRec
	score float64
	why   string
}

// fuzzyBucketCap bounds the files compared pairwise within one name stem.
const fuzzyBucketCap = 400

func fuzzyScan(recs []*fileRec, threshold float64) []fuzzyPair {
	var pairs []fuzzyPair
	// bucket by normalised name stem to keep it tractable
	byStem := map[string][]*fileRec{}
	for _, r := range recs {
		stem := normName(filepath.Base(r.path))
		byStem[stem] = append(byStem[stem], r)
	}
	for _, grp := range byStem {
		if len(grp) > fuzzyBucketCap { // generic stems ("index", "readme") explode pairwise
			grp = grp[:fuzzyBucketCap]
		}
		for i := 0; i < len(grp); i++ {
			for j := i + 1; j < len(grp); j++ {
				// Exact duplicates are already reported as groups; near-duplicate
				// means similar but not byte-identical.
				if grp[i].group >= 0 && grp[i].group == grp[j].group {
					continue
				}
				s, why := similarity(grp[i], grp[j])
				if s >= threshold {
					pairs = append(pairs, fuzzyPair{a: grp[i], b: grp[j], score: s, why: why})
				}
			}
		}
	}
	sort.Slice(pairs, func(i, j int) bool { return pairs[i].score > pairs[j].score })
	return pairs
}

func normName(s string) string {
	s = strings.ToLower(s)
	s = strings.TrimSuffix(s, filepath.Ext(s))
	// strip common copy markers
	for _, m := range []string{" copy", "-copy", "_copy", " (1)", " (2)", "(1)", "(2)", "-1", "-2", " final", " v2", " v1"} {
		s = strings.ReplaceAll(s, m, "")
	}
	return strings.TrimSpace(s)
}

func similarity(a, b *fileRec) (float64, string) {
	nameSim := jaccard(filepath.Base(a.path), filepath.Base(b.path))
	sizeSim := 0.0
	if a.size > 0 && b.size > 0 {
		small, large := a.size, b.size
		if small > large {
			small, large = large, small
		}
		sizeSim = float64(small) / float64(large)
	}
	score := 0.6*nameSim + 0.4*sizeSim
	why := fmt.Sprintf("name=%.2f size=%.2f", nameSim, sizeSim)
	return score, why
}

// jaccard computes character-trigram Jaccard similarity of two strings.
func jaccard(a, b string) float64 {
	ta := trigrams(strings.ToLower(a))
	tb := trigrams(strings.ToLower(b))
	if len(ta) == 0 && len(tb) == 0 {
		return 1
	}
	inter := 0
	for k := range ta {
		if tb[k] {
			inter++
		}
	}
	union := len(ta) + len(tb) - inter
	if union == 0 {
		return 0
	}
	return float64(inter) / float64(union)
}

func trigrams(s string) map[string]bool {
	m := map[string]bool{}
	r := []rune("  " + s + "  ")
	for i := 0; i+3 <= len(r); i++ {
		m[string(r[i:i+3])] = true
	}
	return m
}

// levenshtein distance for close name detection.
func levenshtein(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	prev := make([]int, len(rb)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(ra); i++ {
		cur := make([]int, len(rb)+1)
		cur[0] = i
		for j := 1; j <= len(rb); j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			cur[j] = minI(minI(cur[j-1]+1, prev[j]+1), prev[j-1]+cost)
		}
		prev = cur
	}
	return prev[len(rb)]
}

// ---------------------------------------------------------------------------
// Report builder (findings + posture grade)
// ---------------------------------------------------------------------------

var sensitiveNames = []string{"id_rsa", "id_ed25519", ".env", "credentials", "secret", "password", ".pem", ".key", ".kdbx", "wallet", ".ovpn", "shadow", "htpasswd"}

func looksSensitive(path string) bool {
	low := strings.ToLower(filepath.Base(path))
	for _, s := range sensitiveNames {
		if strings.Contains(low, s) {
			return true
		}
	}
	return false
}

func buildReport(res *scanResult) *Report {
	r := newReport(res.cfg.root)
	wasteRatio := 0.0
	if res.totalBytes > 0 {
		wasteRatio = float64(res.wasted) / float64(res.totalBytes)
	}
	r.Stats = append(r.Stats,
		KV{"root", res.cfg.root},
		KV{"algorithm", res.cfg.algo},
		KV{"files_scanned", commaInt(int64(res.total))},
		KV{"total_size", humanBytes(res.totalBytes)},
		KV{"size_collision_candidates", commaInt(int64(res.candidates))},
		KV{"duplicate_groups", commaInt(int64(len(res.groups)))},
		KV{"reclaimable", humanBytes(res.wasted)},
		KV{"waste_ratio", fmt.Sprintf("%.2f%%", wasteRatio*100)},
		KV{"scan_time", res.elapsed.Round(time.Millisecond).String()},
	)
	dupFiles := 0
	for _, g := range res.groups {
		dupFiles += len(g.files) - 1
	}
	r.Stats = append(r.Stats, KV{"redundant_files", commaInt(int64(dupFiles))})
	if dd := duplicateDirectories(res); len(dd) > 0 {
		r.Stats = append(r.Stats, KV{"duplicate_directories", strconv.Itoa(len(dd))})
		r.Findings = append(r.Findings, Finding{ID: "DEDUPE-DUP-DIR", Title: "Entire directories are duplicated",
			Severity: "LOW", Category: "storage", Score: 2.5,
			Description: fmt.Sprintf("%d sets of directories contain byte-identical file collections; consider consolidating whole trees.", len(dd))})
	}

	// Posture: waste ratio drives severity.
	switch {
	case wasteRatio > 0.4:
		r.Findings = append(r.Findings, Finding{ID: "DEDUPE-WASTE-CRIT", Title: "Severe storage waste from duplicates",
			Severity: "HIGH", Category: "storage", Score: 7.0,
			Description: fmt.Sprintf("%.1f%% of scanned bytes (%s) are redundant duplicate copies.", wasteRatio*100, humanBytes(res.wasted)),
			Remediation: "Review the action plan and consolidate duplicates (hardlink or delete after backup)."})
	case wasteRatio > 0.15:
		r.Findings = append(r.Findings, Finding{ID: "DEDUPE-WASTE-HIGH", Title: "Notable storage waste from duplicates",
			Severity: "MEDIUM", Category: "storage", Score: 5.0,
			Description: fmt.Sprintf("%.1f%% of scanned bytes (%s) are redundant.", wasteRatio*100, humanBytes(res.wasted)),
			Remediation: "Consider de-duplicating the largest groups."})
	case wasteRatio > 0.03:
		r.Findings = append(r.Findings, Finding{ID: "DEDUPE-WASTE-LOW", Title: "Minor duplicate storage waste",
			Severity: "LOW", Category: "storage", Score: 2.0,
			Description: fmt.Sprintf("%.1f%% of scanned bytes are redundant.", wasteRatio*100)})
	}

	// Security-relevant duplicate findings.
	for _, g := range res.groups {
		if looksSensitive(g.files[0].path) {
			paths := []string{}
			for _, f := range g.files {
				paths = append(paths, f.path)
			}
			r.Findings = append(r.Findings, Finding{ID: "DEDUPE-SECRET-COPY", Title: "Sensitive file duplicated across locations",
				Severity: "HIGH", Category: "secret-sprawl", Score: 7.5, ATTCK: []string{"T1552", "T1552.001"},
				Description: "Multiple identical copies of a credential/secret-like file increase exposure surface and the chance one copy is world-readable or backed up insecurely.",
				Evidence:    strings.Join(paths, " | "), Location: g.files[0].path,
				Remediation: "Keep a single authoritative copy with least privilege; remove stray duplicates."})
		}
		for _, f := range g.files {
			if f.mode&0002 != 0 {
				r.Findings = append(r.Findings, Finding{ID: "DEDUPE-WORLD-WRITABLE", Title: "World-writable duplicate file",
					Severity: "MEDIUM", Category: "permissions", Score: 5.0, ATTCK: []string{"T1222"},
					Description: "A duplicate copy is world-writable; attackers can tamper with it independently of the original.",
					Evidence:    fmt.Sprintf("%s mode %o", f.path, f.mode.Perm()), Location: f.path,
					Remediation: "Tighten permissions (chmod o-w) or remove the stray copy."})
				break
			}
		}
		if g.files[0].mode&os.ModeSetuid != 0 {
			r.Findings = append(r.Findings, Finding{ID: "DEDUPE-SUID-COPY", Title: "Duplicated setuid binary",
				Severity: "HIGH", Category: "privilege", Score: 7.0, ATTCK: []string{"T1548.001"},
				Description: "A setuid binary exists in multiple copies, multiplying the privilege-escalation attack surface.",
				Location:    g.files[0].path})
		}
	}

	if len(res.groups) == 0 {
		r.Notes = append(r.Notes, "No exact duplicate content was found under the scan root.")
	}
	if res.linked > 0 {
		r.Stats = append(r.Stats, KV{"already_hardlinked", strconv.Itoa(res.linked) + " copies (not counted as waste)"})
	}
	if hw := len(res.warnings); hw > 0 {
		r.Stats = append(r.Stats, KV{"unreadable_or_skipped", strconv.Itoa(hw)})
	}
	r.Stats = append(r.Stats, ageAnalysis(res)...)
	for _, s := range renameSuggestions(res) {
		if len(r.Notes) < 25 {
			r.Notes = append(r.Notes, "rename: "+s)
		}
	}
	for _, w := range res.warnings {
		if len(r.Notes) < 20 {
			r.Notes = append(r.Notes, w)
		}
	}
	return r
}

// topGroupsRows renders the largest-waste groups for TUI tables.
func topGroupsRows(res *scanResult, n int) [][]string {
	rows := [][]string{}
	for i, g := range res.groups {
		if i >= n {
			break
		}
		rows = append(rows, []string{
			strconv.Itoa(len(g.files)),
			humanBytes(g.size),
			humanBytes(g.wasted),
			truncStr(g.hash, 12),
			truncStr(g.files[0].path, 44),
		})
	}
	return rows
}

// ---------------------------------------------------------------------------
// Size parsing helper
// ---------------------------------------------------------------------------

func parseSize(s string) int64 {
	s = strings.TrimSpace(strings.ToUpper(s))
	if s == "" {
		return 0
	}
	// Accept 512, 512B, 4K, 4KB, 4KIB, 1.5M, 2G, 1T (binary multiples).
	s = strings.TrimSuffix(strings.TrimSuffix(s, "IB"), "B")
	mult := int64(1)
	if n := len(s); n > 0 {
		switch s[n-1] {
		case 'K':
			mult = 1 << 10
		case 'M':
			mult = 1 << 20
		case 'G':
			mult = 1 << 30
		case 'T':
			mult = 1 << 40
		}
		if mult > 1 {
			s = s[:n-1]
		}
	}
	v, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil || v < 0 {
		return 0
	}
	return int64(v * float64(mult))
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

func usage() {
	banner()
	w := os.Stdout
	fmt.Fprintln(w, col("  USAGE", CY+B)+"  "+APPNAME+" [flags]")
	fmt.Fprintln(w, col("  No flags → interactive TUI.  Flags → one-shot CLI. Read-only; never deletes.", GY))
	fmt.Fprintln(w)
	printHelpSection("SCAN", []string{
		"--path DIR         root directory to scan (required for CLI)",
		"--min-size SIZE    ignore files smaller than SIZE (512, 4K, 1.5M, 2G, 1T)",
		"--max-size SIZE    ignore files larger than SIZE",
		"--algo A           hash: sha256 (default), sha1, md5",
		"--workers N        parallel hash workers (default 8)",
		"--ext LIST         comma list of extensions to include (e.g. jpg,png)",
		"--name SUB         only files whose name contains SUB",
		"--hidden           include dotfiles/dotdirs",
		"--exclude GLOBS    comma globs to skip by name (e.g. node_modules,.git,*.tmp)",
		"--follow-symlinks  follow symbolic links to files (hardlink/symlink-aware)",
		"--ext-stats        add per-extension duplicate breakdown",
		"--dir-stats        add directory duplicate hot-spots",
		"--dup-dirs         detect fully-duplicated directories",
		"--histogram        add file-size histogram",
		"--verify           byte-compare dup groups (catch hash collisions)",
		"--largest N        list N largest duplicate files",
		"--empty            count empty (zero-byte) files",
		"--manifest FILE    save a content manifest and exit",
		"--baseline FILE    diff current tree against a saved manifest",
		"--list             print a detailed listing of every duplicate group",
		"--groups-json FILE export duplicate groups as JSON",
		"--groups-csv FILE  export duplicate groups as CSV",
		"--reference        print duplicate-prone file-type guidance",
	})
	printHelpSection("FUZZY", []string{
		"--fuzzy            also report near-duplicates (similar, not byte-identical)",
		"--fuzzy-threshold  similarity 0..1 (default 0.75)",
	})
	printHelpSection("ACTION PLAN (never auto-executed)", []string{
		"--plan OP          delete | hardlink | move",
		"--strategy S       keep-oldest (default) | keep-newest | keep-shortest-path",
		"--move-dir DIR     destination for --plan move (required for move)",
		"--prefer PREFIX    always keep the copy under PREFIX when a group has one",
		"--script FILE      write a reviewable shell script (each action cmp-guarded)",
	})
	printHelpSection("REPORTING", []string{
		"--format FMT       txt|md|json|csv|sarif (default txt)",
		"--output FILE      write report to FILE (default stdout)",
		"--no-color         disable ANSI colour",
	})
	printHelpSection("GENERAL", []string{
		"--demo             self-contained demo on synthetic temp files",
		"--selftest         internal correctness tests",
		"--version          print version",
		"-h, --help         this help",
	})
	printHelpSection("EXAMPLES", []string{
		APPNAME + " --path ~/Downloads --min-size 1M --fuzzy",
		APPNAME + " --path /data --plan hardlink --script plan.sh",
		APPNAME + " --path . --format json --output dups.json",
	})
	line(64)
}

func printVersion() {
	fmt.Printf("%s v%s — %s\n", APPNAME, VERSION, SUITE)
	fmt.Printf("Author : %s\nWebsite: %s\n", AUTHOR, WEBSITE)
	fmt.Println("Build  : Go stdlib, static (CGO disabled)")
}

var lastResult *scanResult
var lastReport *Report

func main() {
	var (
		path     string
		minSize  string
		maxSize  string
		algo     string
		workers  int
		ext      string
		namePat  string
		hidden   bool
		follow   bool
		fuzzy    bool
		fuzzyThr float64
		plan     string
		strategy string
		moveDir  string
		script   string
		format   string
		output   string
		nocolor  bool
		demo     bool
		selftest bool
		showVer  bool
	)
	fs := flag.NewFlagSet(APPNAME, flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fs.Usage = usage
	fs.StringVar(&path, "path", "", "")
	fs.StringVar(&path, "target", "", "")
	fs.StringVar(&minSize, "min-size", "1", "")
	fs.StringVar(&maxSize, "max-size", "0", "")
	fs.StringVar(&algo, "algo", "sha256", "")
	fs.IntVar(&workers, "workers", 8, "")
	fs.StringVar(&ext, "ext", "", "")
	fs.StringVar(&namePat, "name", "", "")
	fs.BoolVar(&hidden, "hidden", false, "")
	fs.BoolVar(&follow, "follow-symlinks", false, "")
	fs.BoolVar(&fuzzy, "fuzzy", false, "")
	fs.Float64Var(&fuzzyThr, "fuzzy-threshold", 0.75, "")
	fs.StringVar(&plan, "plan", "", "")
	fs.StringVar(&strategy, "strategy", "keep-oldest", "")
	fs.StringVar(&moveDir, "move-dir", "", "")
	fs.StringVar(&script, "script", "", "")
	fs.StringVar(&format, "format", "txt", "")
	fs.StringVar(&output, "output", "", "")
	fs.BoolVar(&nocolor, "no-color", false, "")
	fs.BoolVar(&demo, "demo", false, "")
	fs.BoolVar(&selftest, "selftest", false, "")
	fs.BoolVar(&showVer, "version", false, "")
	extStatsF := fs.Bool("ext-stats", false, "")
	dirStatsF := fs.Bool("dir-stats", false, "")
	dupDirsF := fs.Bool("dup-dirs", false, "")
	histoF := fs.Bool("histogram", false, "")
	verifyF := fs.Bool("verify", false, "")
	largestF := fs.Int("largest", 0, "")
	emptyF := fs.Bool("empty", false, "")
	manifestOut := fs.String("manifest", "", "")
	baselineF := fs.String("baseline", "", "")
	listF := fs.Bool("list", false, "")
	groupsJSONF := fs.String("groups-json", "", "")
	groupsCSVF := fs.String("groups-csv", "", "")
	referenceF := fs.Bool("reference", false, "")
	excludeF := fs.String("exclude", "", "")
	preferF := fs.String("prefer", "", "")
	if err := fs.Parse(os.Args[1:]); err != nil {
		if err == flag.ErrHelp {
			return
		}
		errMsg(err.Error())
		os.Exit(2)
	}
	if nocolor {
		noColor = true
	}
	switch {
	case *referenceF:
		banner()
		printDupReference()
		return
	case showVer:
		printVersion()
		return
	case selftest:
		runSelfTest()
		return
	case demo:
		runDemo(format, output)
		return
	case path != "":
		cfg := defaultConfig(path)
		cfg.minSize = parseSize(minSize)
		if cfg.minSize < 1 {
			cfg.minSize = 1
		}
		cfg.maxSize = parseSize(maxSize)
		cfg.algo = algo
		cfg.workers = workers
		cfg.includeHid = hidden
		cfg.followLinks = follow
		cfg.namePat = namePat
		if ext != "" {
			cfg.exts = strings.Split(ext, ",")
		}
		if *excludeF != "" {
			cfg.excludes = splitTrim(*excludeF)
		}
		cfg.prefer = *preferF
		if *manifestOut != "" {
			m, err := buildManifest(cfg)
			if err != nil {
				errMsg(err.Error())
				os.Exit(1)
			}
			if err := saveManifest(m, *manifestOut); err != nil {
				errMsg(err.Error())
				os.Exit(1)
			}
			okMsg(fmt.Sprintf("saved manifest of %d files to %s", len(m.Entries), *manifestOut))
			return
		}
		if *baselineF != "" {
			old, err := loadManifest(*baselineF)
			if err != nil {
				errMsg(err.Error())
				os.Exit(1)
			}
			cur, err := buildManifest(cfg)
			if err != nil {
				errMsg(err.Error())
				os.Exit(1)
			}
			df := diffManifests(old, cur)
			rep := newReport(path)
			rep.Stats = append(rep.Stats,
				KV{"baseline", *baselineF},
				KV{"added", strconv.Itoa(len(df.added))},
				KV{"removed", strconv.Itoa(len(df.removed))},
				KV{"modified", strconv.Itoa(len(df.modified))},
				KV{"moved", strconv.Itoa(len(df.moved))})
			for _, p := range df.modified {
				rep.Findings = append(rep.Findings, Finding{ID: "DEDUPE-CHANGED", Title: "File content changed since baseline",
					Severity: "MEDIUM", Category: "integrity", Score: 5.0, ATTCK: []string{"T1565.001"},
					Description: "File hash differs from the recorded baseline.", Location: p})
			}
			_ = emit(rep, format, output)
			return
		}
		res, err := runScan(cfg)
		if err != nil {
			errMsg(err.Error())
			os.Exit(1)
		}
		rep := buildReport(res)
		if *extStatsF {
			for i, s := range extensionStats(res) {
				if i >= 8 {
					break
				}
				rep.Stats = append(rep.Stats, KV{"ext:" + s.ext, fmt.Sprintf("%d files / %s", s.count, humanBytes(s.bytes))})
			}
		}
		if *dirStatsF {
			for i, s := range directoryStats(res) {
				if i >= 8 {
					break
				}
				rep.Stats = append(rep.Stats, KV{"dir:" + truncStr(s.dir, 40), humanBytes(s.wasted)})
			}
		}
		if *dupDirsF {
			rep.Stats = append(rep.Stats, KV{"duplicate_directory_sets", strconv.Itoa(len(duplicateDirectories(res)))})
		}
		if *histoF {
			rep.Stats = append(rep.Stats, sizeHistogram(allRecs(res))...)
		}
		if *verifyF {
			conf, mis := verifyGroups(res)
			rep.Stats = append(rep.Stats, KV{"byte_verified_pairs", strconv.Itoa(conf)}, KV{"hash_collisions_detected", strconv.Itoa(mis)})
			if mis > 0 {
				rep.Findings = append(rep.Findings, Finding{ID: "DEDUPE-HASH-COLLISION", Title: "Hash collision (bytes differ)",
					Severity: "CRITICAL", Category: "integrity", Score: 9.0,
					Description: fmt.Sprintf("%d file pairs shared a hash but differ byte-for-byte — do NOT treat as duplicates.", mis)})
			}
		}
		if *largestF > 0 {
			for _, f := range largestFiles(allRecs(res), *largestF) {
				rep.Stats = append(rep.Stats, KV{"large:" + truncStr(filepath.Base(f.path), 32), humanBytes(f.size)})
			}
		}
		if *emptyF {
			rep.Stats = append(rep.Stats, KV{"empty_files", strconv.Itoa(len(emptyFiles(cfg)))})
		}
		if fuzzy {
			fp := fuzzyScan(res.all, fuzzyThr)
			rep.Stats = append(rep.Stats, KV{"fuzzy_pairs", strconv.Itoa(len(fp))})
			for i, p := range fp {
				if i >= 50 {
					break
				}
				rep.Findings = append(rep.Findings, Finding{ID: "DEDUPE-FUZZY", Title: "Near-duplicate files",
					Severity: "INFO", Category: "fuzzy", Score: 0,
					Description: fmt.Sprintf("similarity %.2f (%s)", p.score, p.why),
					Evidence:    p.a.path + " ~ " + p.b.path, Location: p.a.path})
			}
		}
		if plan != "" {
			if plan == "move" && moveDir == "" {
				errMsg("--plan move requires --move-dir DIR")
				os.Exit(2)
			}
			pc := planConfig{strategy: strategy, op: plan, moveDir: moveDir, prefer: cfg.prefer}
			pl := buildPlan(res, pc)
			rep.Stats = append(rep.Stats, KV{"plan_op", plan}, KV{"plan_reclaim", humanBytes(reclaimableBytes(pl))})
			if script != "" {
				if err := os.WriteFile(script, []byte(writePlanScript(pl)), 0755); err != nil {
					errMsg(err.Error())
				} else {
					okMsg("wrote reviewable plan script to " + script)
				}
			}
		}
		if *listF {
			fmt.Print(listAllGroups(res))
		}
		if *groupsJSONF != "" {
			if err := os.WriteFile(*groupsJSONF, []byte(exportGroupsJSON(res)), 0644); err != nil {
				errMsg(err.Error())
			} else {
				okMsg("wrote group JSON to " + *groupsJSONF)
			}
		}
		if *groupsCSVF != "" {
			if err := os.WriteFile(*groupsCSVF, []byte(exportGroupsCSV(res)), 0644); err != nil {
				errMsg(err.Error())
			} else {
				okMsg("wrote group CSV to " + *groupsCSVF)
			}
		}
		for _, rc := range recommendations(res) {
			rep.Notes = append(rep.Notes, "advice: "+rc)
		}
		if err := emit(rep, format, output); err != nil {
			errMsg(err.Error())
			os.Exit(1)
		}
		return
	default:
		interactive()
	}
}

// splitTrim splits a comma list and drops blanks.
func splitTrim(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func allRecs(res *scanResult) []*fileRec {
	var out []*fileRec
	for _, g := range res.groups {
		out = append(out, g.files...)
	}
	return out
}

// ---------------------------------------------------------------------------
// Demo + self-test
// ---------------------------------------------------------------------------

func runDemo(format, output string) {
	banner()
	info("creating a synthetic directory tree with duplicate content in a temp dir")
	dir, err := os.MkdirTemp("", "odedupe-demo-")
	if err != nil {
		errMsg(err.Error())
		return
	}
	defer os.RemoveAll(dir)
	payloadA := []byte(strings.Repeat("OWL-DUPLICATE-PAYLOAD-ALPHA-", 400))
	payloadB := []byte(strings.Repeat("unique-content-beta-", 300))
	secret := []byte("-----BEGIN PRIVATE KEY-----\nMOCKKEY\n-----END PRIVATE KEY-----\n")
	files := map[string][]byte{
		"docs/report.txt":      payloadA,
		"docs/report copy.txt": payloadA,
		"backup/report.txt":    payloadA,
		"notes/beta.txt":       payloadB,
		"notes/beta (1).txt":   payloadB,
		"keys/id_rsa":          secret,
		"keys/backup/id_rsa":   secret,
		"misc/unique.bin":      []byte("singleton"),
	}
	for rel, data := range files {
		full := filepath.Join(dir, rel)
		os.MkdirAll(filepath.Dir(full), 0755)
		os.WriteFile(full, data, 0644)
	}
	cfg := defaultConfig(dir)
	cfg.workers = 4
	res, err := runScan(cfg)
	if err != nil {
		errMsg(err.Error())
		return
	}
	fmt.Println()
	okMsg(fmt.Sprintf("scanned %d files, found %d duplicate groups", res.total, len(res.groups)))
	fmt.Println()
	table([]string{"COPIES", "SIZE", "WASTED", "HASH", "KEEPER"}, topGroupsRows(res, 10))
	fmt.Println()
	pc := planConfig{strategy: "keep-oldest", op: "hardlink"}
	pl := buildPlan(res, pc)
	okMsg("example plan (hardlink) would reclaim " + humanBytes(reclaimableBytes(pl)))
	fmt.Println()
	rep := buildReport(res)
	rep.Notes = append(rep.Notes, "Demo data is synthetic and the temp tree is removed on exit.")
	showFindingsTUI(rep)
	fmt.Println()
	if output != "" || format != "txt" {
		_ = emit(rep, format, output)
	}
	okMsg("demo complete")
}

func runSelfTest() {
	banner()
	info("running internal self-tests")
	fmt.Println()
	pass, fail := 0, 0
	check := func(name string, cond bool) {
		if cond {
			pass++
			okMsg(name)
		} else {
			fail++
			errMsg(name)
		}
	}
	check("jaccard identical == 1", jaccard("hello.txt", "hello.txt") == 1)
	check("jaccard disjoint low", jaccard("abcdef", "zyxwvu") < 0.2)
	check("levenshtein kitten/sitting == 3", levenshtein("kitten", "sitting") == 3)
	check("parseSize 1K == 1024", parseSize("1K") == 1024)
	check("parseSize 2M", parseSize("2M") == 2*1024*1024)
	check("normName strips copy", normName("report copy.txt") == "report")
	check("matchExt jpg", matchExt("a.JPG", []string{"jpg"}))
	// hashing determinism via temp files
	dir, _ := os.MkdirTemp("", "odedupe-st-")
	defer os.RemoveAll(dir)
	p1 := filepath.Join(dir, "a")
	p2 := filepath.Join(dir, "b")
	os.WriteFile(p1, []byte("same-bytes"), 0644)
	os.WriteFile(p2, []byte("same-bytes"), 0644)
	h1, _ := hashFileFull(p1, "sha256")
	h2, _ := hashFileFull(p2, "sha256")
	check("identical content same hash", h1 == h2 && h1 != "")
	os.WriteFile(p2, []byte("different"), 0644)
	h3, _ := hashFileFull(p2, "sha256")
	check("different content different hash", h1 != h3)
	// end-to-end scan
	os.WriteFile(p2, []byte("same-bytes"), 0644)
	res, _ := runScan(defaultConfig(dir))
	check("scan finds one dup group", len(res.groups) == 1)
	keep := chooseKeeper(res.groups[0].files, "keep-shortest-path")
	check("chooseKeeper returns valid index", keep >= 0 && keep < len(res.groups[0].files))
	check("chooseKeeper honours --prefer", chooseKeeper([]*fileRec{{path: "/a/f"}, {path: "/keep/f"}}, "keep-shortest-path", "/keep/") == 1)

	check("parseSize 512B == 512", parseSize("512B") == 512)
	check("parseSize 1.5G", parseSize("1.5G") == 3*(1<<29))
	check("parseSize 4KiB", parseSize("4KiB") == 4096)
	check("exclude glob matches", excluded("node_modules", []string{".git", "node_*"}) && !excluded("src", []string{"node_*"}))

	// Hardlinks share storage: two names, one inode -> no waste, no plan action.
	p3 := filepath.Join(dir, "c")
	os.Link(p1, p3)
	res, _ = runScan(defaultConfig(dir))
	check("hardlink not counted as waste", len(res.groups) == 1 && res.linked == 1 && res.wasted == int64(len("same-bytes")))
	dels := 0
	for _, a := range buildPlan(res, planConfig{op: "delete"}) {
		if a.op == "DELETE" {
			dels++
		}
	}
	check("plan skips already-hardlinked copy", dels == 1)

	// Symlink to a duplicate is followed and resolved to its target's inode;
	// the plan must never delete the data a symlink keeper points at.
	link := filepath.Join(dir, "d-link")
	os.Symlink(p2, link)
	cfgL := defaultConfig(dir)
	cfgL.followLinks = true
	resL, _ := runScan(cfgL)
	check("follow-symlinks scans link targets", len(resL.all) == 4)
	safe := true
	keepPath := ""
	for _, a := range buildPlan(resL, planConfig{op: "delete", strategy: "keep-shortest-path"}) {
		if a.op == "KEEP" {
			keepPath = a.path
		}
		if a.op == "DELETE" && ((keepPath == link && a.path == p2) || (keepPath == p2 && a.path == link)) {
			safe = false
		}
	}
	check("symlink and its target never delete each other", safe)

	// Move plan: the same basename in two groups must not collide.
	mres := &scanResult{groups: []dupGroup{
		{files: []*fileRec{{path: "/a/x.txt"}, {path: "/b/x.txt"}}},
		{files: []*fileRec{{path: "/c/x.txt"}, {path: "/d/x.txt"}}},
	}}
	dsts := map[string]bool{}
	collide := false
	for _, a := range buildPlan(mres, planConfig{op: "move", moveDir: "/q"}) {
		if a.op == "MOVE" {
			collide = collide || dsts[a.target]
			dsts[a.target] = true
		}
	}
	check("move plan gives unique destinations", !collide && len(dsts) == 2)
	check("plan script guards with cmp", strings.Contains(writePlanScript(buildPlan(res, planConfig{op: "delete"})), "cmp -s -- "))

	// Fuzzy looks beyond exact groups: a near-copy is found.
	fdir, _ := os.MkdirTemp("", "odedupe-fz-")
	defer os.RemoveAll(fdir)
	os.WriteFile(filepath.Join(fdir, "report.txt"), []byte(strings.Repeat("a", 1000)), 0644)
	os.WriteFile(filepath.Join(fdir, "report copy.txt"), []byte(strings.Repeat("b", 990)), 0644)
	fres, _ := runScan(defaultConfig(fdir))
	check("fuzzy finds non-identical near-copy", len(fres.groups) == 0 && len(fuzzyScan(fres.all, 0.5)) == 1)

	// A duplicate directory needs ALL its files duplicated, not one shared file.
	ddir, _ := os.MkdirTemp("", "odedupe-dd-")
	defer os.RemoveAll(ddir)
	for _, rel := range []string{"x/1", "y/1", "z/1"} {
		os.MkdirAll(filepath.Join(ddir, filepath.Dir(rel)), 0755)
		os.WriteFile(filepath.Join(ddir, rel), []byte("shared"), 0644)
	}
	os.WriteFile(filepath.Join(ddir, "z", "only-in-z"), []byte("unique"), 0644)
	dres, _ := runScan(defaultConfig(ddir))
	dd := duplicateDirectories(dres)
	check("dup-dirs pairs x/y, excludes partial z", len(dd) == 1 && len(dd[0]) == 2 && !strings.HasSuffix(dd[0][1], "z"))

	fmt.Println()
	if fail == 0 {
		okMsg(fmt.Sprintf("all %d self-tests passed", pass))
	} else {
		errMsg(fmt.Sprintf("%d passed, %d failed", pass, fail))
		os.Exit(1)
	}
}

// ---------------------------------------------------------------------------
// Interactive TUI
// ---------------------------------------------------------------------------

// tuiActions is the interactive menu, in display order; the dispatcher below
// indexes the same slice, so labels and handlers cannot drift apart.
var tuiActions = []struct {
	name, desc string
	run        func()
}{
	{"Scan a directory", "Exact duplicates: size → head → full hash", tuiScan},
	{"Fuzzy near-duplicate scan", "Similar names + sizes, not exact copies", tuiFuzzy},
	{"Top waste groups", "Largest reclaimable duplicate groups", tuiTop},
	{"Build action plan (dry-run)", "Preview delete / hardlink / move", tuiPlan},
	{"Write reviewable plan script", "Shell script with cmp safety guards", tuiScript},
	{"Export last report", "txt / md / json / csv / sarif", tuiExport},
	{"Extension statistics", "Duplicate bytes per file extension", tuiExtStats},
	{"Directory hot-spots", "Directories holding the most waste", tuiDirStats},
	{"Duplicate directories", "Whole directories with identical content", tuiDupDirs},
	{"Size histogram", "Duplicate files by size bucket", tuiHist},
	{"Byte-exact verify", "Byte-compare groups, rule out collisions", tuiVerify},
	{"List all groups", "Every group with keeper and copies", tuiListGroups},
	{"Age analysis", "Modification-time spread of duplicates", tuiAge},
	{"Health card", "Grade, reclaimable bytes, waste by kind", tuiHealth},
	{"File-type reference & advice", "Duplicate-prone types and guidance", tuiReference},
	{"Self-test", "Built-in correctness checks", func() { clear(); runSelfTest(); pause() }},
}

func interactive() {
	for {
		items := make([]menuItem, len(tuiActions))
		for i, a := range tuiActions {
			items[i] = menuItem{key: fmt.Sprintf("%02d", i+1), name: a.name, desc: a.desc, clr: CY + B}
		}
		choice := strings.TrimSpace(menu(TAGLINE, items))
		if choice == "0" || choice == "00" || strings.EqualFold(choice, "q") || strings.EqualFold(choice, "exit") {
			clear()
			banner()
			okMsg("Session closed. Read-only by design — nothing was modified.")
			return
		}
		if strings.EqualFold(choice, "h") || strings.EqualFold(choice, "help") || choice == "?" {
			tuiHelp()
			continue
		}
		// Accept both "1" and the displayed "01".
		n, err := strconv.Atoi(choice)
		if err != nil || n < 1 || n > len(tuiActions) {
			if choice != "" {
				warnMsg("unknown selection")
				pause()
			}
			continue
		}
		tuiActions[n-1].run()
	}
}

func tuiScan() {
	clear()
	banner()
	p := prompt("directory to scan")
	if p == "" {
		return
	}
	cfg := defaultConfig(p)
	cfg.minSize = parseSize(prompt("min size (e.g. 1K, blank=1)"))
	if cfg.minSize < 1 {
		cfg.minSize = 1
	}
	algo := prompt("algo sha256/sha1/md5 (blank=sha256)")
	if algo != "" {
		cfg.algo = algo
	}
	cfg.excludes = splitTrim(prompt("exclude globs, comma list (blank=none)"))
	info("scanning...")
	res, err := runScan(cfg)
	if err != nil {
		errMsg(err.Error())
		pause()
		return
	}
	lastResult = res
	lastReport = buildReport(res)
	fmt.Println()
	sectionHeader("Scan summary")
	kvTable(lastReport.Stats)
	fmt.Println()
	showFindingsTUI(lastReport)
	pause()
}

func tuiFuzzy() {
	clear()
	banner()
	if lastResult == nil {
		warnMsg("run a scan first")
		pause()
		return
	}
	thr := 0.75
	if v, err := strconv.ParseFloat(prompt("threshold 0..1 (blank=0.75)"), 64); err == nil {
		thr = v
	}
	fp := fuzzyScan(lastResult.all, thr)
	rows := [][]string{}
	for i, p := range fp {
		if i >= 20 {
			break
		}
		rows = append(rows, []string{fmt.Sprintf("%.2f", p.score), truncStr(filepath.Base(p.a.path), 24), truncStr(filepath.Base(p.b.path), 24)})
	}
	if len(rows) == 0 {
		okMsg("no near-duplicates above threshold")
	} else {
		table([]string{"SCORE", "A", "B"}, rows)
	}
	pause()
}

func tuiTop() {
	clear()
	banner()
	if lastResult == nil {
		warnMsg("run a scan first")
		pause()
		return
	}
	table([]string{"COPIES", "SIZE", "WASTED", "HASH", "KEEPER"}, topGroupsRows(lastResult, 20))
	pause()
}

func tuiPlan() {
	clear()
	banner()
	if lastResult == nil {
		warnMsg("run a scan first")
		pause()
		return
	}
	op := prompt("op delete/hardlink/move (blank=delete)")
	if op == "" {
		op = "delete"
	}
	strat := prompt("strategy keep-oldest/keep-newest/keep-shortest-path")
	if strat == "" {
		strat = "keep-oldest"
	}
	pc := planConfig{strategy: strat, op: op}
	if op == "move" {
		if pc.moveDir = prompt("move destination dir"); pc.moveDir == "" {
			warnMsg("move needs a destination directory")
			pause()
			return
		}
	}
	pl := buildPlan(lastResult, pc)
	okMsg(fmt.Sprintf("plan has %d actions; would reclaim %s", len(pl), humanBytes(reclaimableBytes(pl))))
	shown := 0
	for _, a := range pl {
		if a.op == "KEEP" {
			continue
		}
		info(a.op + " " + truncStr(a.path, 50))
		shown++
		if shown >= 15 {
			info("... (truncated)")
			break
		}
	}
	warnMsg("this is a DRY-RUN preview; ODedupe never modifies files")
	pause()
}

func tuiScript() {
	clear()
	banner()
	if lastResult == nil {
		warnMsg("run a scan first")
		pause()
		return
	}
	op := prompt("op delete/hardlink/move")
	if op == "" {
		op = "delete"
	}
	path := prompt("script output path")
	if path == "" {
		return
	}
	pc := planConfig{strategy: "keep-oldest", op: op}
	if op == "move" {
		if pc.moveDir = prompt("move destination dir"); pc.moveDir == "" {
			warnMsg("move needs a destination directory")
			pause()
			return
		}
	}
	pl := buildPlan(lastResult, pc)
	if err := os.WriteFile(path, []byte(writePlanScript(pl)), 0755); err != nil {
		errMsg(err.Error())
	} else {
		okMsg("wrote reviewable script to " + path + " — inspect before running")
	}
	pause()
}

func tuiExport() {
	clear()
	banner()
	if lastReport == nil {
		warnMsg("no report yet — run a scan first")
		pause()
		return
	}
	f := prompt("format txt/md/json/csv/sarif")
	o := prompt("output file (blank=stdout)")
	if err := emit(lastReport, f, o); err != nil {
		errMsg(err.Error())
	}
	pause()
}

// ---------------------------------------------------------------------------
// Part 6 — extension/dir statistics, duplicate-directory detection, size
// histogram, manifest baseline + diff, byte-exact verification, largest/empty.
// ---------------------------------------------------------------------------

type extStat struct {
	ext   string
	count int
	bytes int64
	dups  int
}

func extensionStats(res *scanResult) []extStat {
	m := map[string]*extStat{}
	for _, g := range res.groups {
		for _, f := range g.files {
			e := strings.ToLower(filepath.Ext(f.path))
			if e == "" {
				e = "(none)"
			}
			if m[e] == nil {
				m[e] = &extStat{ext: e}
			}
			m[e].count++
			m[e].bytes += f.size
			m[e].dups++
		}
	}
	var out []extStat
	for _, v := range m {
		out = append(out, *v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].bytes > out[j].bytes })
	return out
}

func allExtensionStats(recs []*fileRec) []extStat {
	m := map[string]*extStat{}
	for _, f := range recs {
		e := strings.ToLower(filepath.Ext(f.path))
		if e == "" {
			e = "(none)"
		}
		if m[e] == nil {
			m[e] = &extStat{ext: e}
		}
		m[e].count++
		m[e].bytes += f.size
	}
	var out []extStat
	for _, v := range m {
		out = append(out, *v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].bytes > out[j].bytes })
	return out
}

func printExtStats(stats []extStat, totalBytes int64) {
	rows := [][]string{}
	for i, s := range stats {
		if i >= 20 {
			break
		}
		frac := 0.0
		if totalBytes > 0 {
			frac = float64(s.bytes) / float64(totalBytes)
		}
		rows = append(rows, []string{s.ext, strconv.Itoa(s.count), humanBytes(s.bytes), asciiBar(frac, 16)})
	}
	table([]string{"EXT", "FILES", "BYTES", "SHARE"}, rows)
}

// ---------------------------------------------------------------------------
// Directory-level duplicate concentration
// ---------------------------------------------------------------------------

type dirStat struct {
	dir    string
	dups   int
	wasted int64
}

func directoryStats(res *scanResult) []dirStat {
	m := map[string]*dirStat{}
	for _, g := range res.groups {
		for i, f := range g.files {
			if i == 0 {
				continue // first is the keeper
			}
			d := filepath.Dir(f.path)
			if m[d] == nil {
				m[d] = &dirStat{dir: d}
			}
			m[d].dups++
			m[d].wasted += f.size
		}
	}
	var out []dirStat
	for _, v := range m {
		out = append(out, *v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].wasted > out[j].wasted })
	return out
}

func printDirStats(stats []dirStat) {
	rows := [][]string{}
	for i, s := range stats {
		if i >= 20 {
			break
		}
		rows = append(rows, []string{strconv.Itoa(s.dups), humanBytes(s.wasted), truncStr(s.dir, 50)})
	}
	table([]string{"REDUNDANT", "WASTED", "DIRECTORY"}, rows)
}

// ---------------------------------------------------------------------------
// Duplicate-directory detection: directories whose file-content sets match.
// ---------------------------------------------------------------------------

// duplicateDirectories finds directories whose entire (filtered) file set is
// byte-identical to another directory's. A directory qualifies only when every
// file in it belongs to a duplicate group — sharing a few duplicates with
// another directory does not make the two directories copies of each other.
func duplicateDirectories(res *scanResult) [][]string {
	perDir := map[string][]*fileRec{}
	for _, f := range res.all {
		d := filepath.Dir(f.path)
		perDir[d] = append(perDir[d], f)
	}
	byFP := map[string][]string{}
	for d, files := range perDir {
		sums := make([]string, 0, len(files))
		whole := true
		for _, f := range files {
			if f.group < 0 || f.fullSum == "" {
				whole = false
				break
			}
			sums = append(sums, f.fullSum)
		}
		if !whole {
			continue
		}
		sort.Strings(sums)
		h := sha256.Sum256([]byte(strings.Join(sums, "|")))
		fp := hex.EncodeToString(h[:])
		byFP[fp] = append(byFP[fp], d)
	}
	var out [][]string
	for _, grp := range byFP {
		if len(grp) > 1 {
			sort.Strings(grp)
			out = append(out, grp)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i][0] < out[j][0] })
	return out
}

// ---------------------------------------------------------------------------
// Size histogram
// ---------------------------------------------------------------------------

func sizeHistogram(recs []*fileRec) []KV {
	buckets := []struct {
		label string
		lo    int64
		hi    int64
	}{
		{"0-1K", 0, 1024},
		{"1K-10K", 1024, 10 * 1024},
		{"10K-100K", 10 * 1024, 100 * 1024},
		{"100K-1M", 100 * 1024, 1024 * 1024},
		{"1M-10M", 1024 * 1024, 10 * 1024 * 1024},
		{"10M-100M", 10 * 1024 * 1024, 100 * 1024 * 1024},
		{"100M-1G", 100 * 1024 * 1024, 1024 * 1024 * 1024},
		{">1G", 1024 * 1024 * 1024, 1 << 62},
	}
	counts := make([]int, len(buckets))
	maxC := 1
	for _, f := range recs {
		for i, b := range buckets {
			if f.size >= b.lo && f.size < b.hi {
				counts[i]++
				if counts[i] > maxC {
					maxC = counts[i]
				}
				break
			}
		}
	}
	var out []KV
	for i, b := range buckets {
		out = append(out, KV{b.label, fmt.Sprintf("%5d %s", counts[i], asciiBar(float64(counts[i])/float64(maxC), 24))})
	}
	return out
}

// ---------------------------------------------------------------------------
// Manifest baseline + diff (save a content map, compare later)
// ---------------------------------------------------------------------------

type manifestEntry struct {
	Path string `json:"path"`
	Size int64  `json:"size"`
	Hash string `json:"hash"`
}

type manifest struct {
	Root    string          `json:"root"`
	Algo    string          `json:"algo"`
	Created string          `json:"created"`
	Entries []manifestEntry `json:"entries"`
}

func buildManifest(cfg scanConfig) (*manifest, error) {
	recs, _, err := collectFiles(cfg)
	if err != nil {
		return nil, err
	}
	hashParallel(recs, cfg, false)
	m := &manifest{Root: cfg.root, Algo: cfg.algo, Created: time.Now().Format(time.RFC3339)}
	for _, r := range recs {
		m.Entries = append(m.Entries, manifestEntry{Path: r.path, Size: r.size, Hash: r.fullSum})
	}
	return m, nil
}

func saveManifest(m *manifest, path string) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(m); err != nil {
		return err
	}
	return os.WriteFile(path, buf.Bytes(), 0644)
}

func loadManifest(path string) (*manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

type manifestDiff struct {
	added    []string
	removed  []string
	modified []string
	moved    [][2]string
}

func diffManifests(old, cur *manifest) manifestDiff {
	var d manifestDiff
	oldByPath := map[string]manifestEntry{}
	oldByHash := map[string]string{}
	for _, e := range old.Entries {
		oldByPath[e.Path] = e
		oldByHash[e.Hash] = e.Path
	}
	curByPath := map[string]manifestEntry{}
	curHashes := map[string]bool{}
	for _, e := range cur.Entries {
		curByPath[e.Path] = e
		curHashes[e.Hash] = true
		if o, ok := oldByPath[e.Path]; ok {
			if o.Hash != e.Hash {
				d.modified = append(d.modified, e.Path)
			}
		} else {
			if op, ok := oldByHash[e.Hash]; ok {
				d.moved = append(d.moved, [2]string{op, e.Path})
			} else {
				d.added = append(d.added, e.Path)
			}
		}
	}
	for _, e := range old.Entries {
		if _, ok := curByPath[e.Path]; !ok {
			if !curHashes[e.Hash] {
				d.removed = append(d.removed, e.Path)
			}
		}
	}
	return d
}

// ---------------------------------------------------------------------------
// Byte-exact verification (defends against hash collisions)
// ---------------------------------------------------------------------------

func bytesEqual(p1, p2 string) (bool, error) {
	f1, err := os.Open(p1)
	if err != nil {
		return false, err
	}
	defer f1.Close()
	f2, err := os.Open(p2)
	if err != nil {
		return false, err
	}
	defer f2.Close()
	b1 := make([]byte, 65536)
	b2 := make([]byte, 65536)
	for {
		// ReadFull keeps both files in lock-step; plain Read may return short
		// counts that differ between files and fake a mismatch.
		n1, e1 := io.ReadFull(f1, b1)
		n2, e2 := io.ReadFull(f2, b2)
		if e1 == io.ErrUnexpectedEOF {
			e1 = io.EOF
		}
		if e2 == io.ErrUnexpectedEOF {
			e2 = io.EOF
		}
		if n1 != n2 {
			return false, nil
		}
		if !byteSliceEq(b1[:n1], b2[:n2]) {
			return false, nil
		}
		if e1 == io.EOF && e2 == io.EOF {
			return true, nil
		}
		if (e1 == io.EOF) != (e2 == io.EOF) {
			return false, nil
		}
		if e1 != nil && e1 != io.EOF {
			return false, e1
		}
		if e2 != nil && e2 != io.EOF {
			return false, e2
		}
	}
}

func byteSliceEq(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func verifyGroups(res *scanResult) (confirmed, mismatched int) {
	for _, g := range res.groups {
		keeper := g.files[0].path
		for _, f := range g.files[1:] {
			eq, err := bytesEqual(keeper, f.path)
			if err != nil {
				continue
			}
			if eq {
				confirmed++
			} else {
				mismatched++
			}
		}
	}
	return
}

// ---------------------------------------------------------------------------
// Largest / empty files
// ---------------------------------------------------------------------------

func largestFiles(recs []*fileRec, n int) []*fileRec {
	cp := make([]*fileRec, len(recs))
	copy(cp, recs)
	sort.Slice(cp, func(i, j int) bool { return cp[i].size > cp[j].size })
	if len(cp) > n {
		cp = cp[:n]
	}
	return cp
}

func emptyFiles(cfg scanConfig) []string {
	c := cfg
	c.minSize = 0
	c.maxSize = 0
	recs, _, _ := collectFiles(c)
	var out []string
	for _, r := range recs {
		if r.size == 0 {
			out = append(out, r.path)
		}
	}
	return out
}

func requireScan() bool {
	if lastResult == nil {
		warnMsg("run a scan first")
		pause()
		return false
	}
	return true
}
func tuiExtStats() {
	clear()
	banner()
	if !requireScan() {
		return
	}
	printExtStats(extensionStats(lastResult), lastResult.totalBytes)
	pause()
}
func tuiDirStats() {
	clear()
	banner()
	if !requireScan() {
		return
	}
	printDirStats(directoryStats(lastResult))
	pause()
}
func tuiDupDirs() {
	clear()
	banner()
	if !requireScan() {
		return
	}
	dd := duplicateDirectories(lastResult)
	if len(dd) == 0 {
		okMsg("no fully-duplicated directories detected")
	} else {
		for _, grp := range dd {
			okMsg("duplicate set:")
			for _, p := range grp {
				info("  " + p)
			}
		}
	}
	pause()
}
func tuiHist() {
	clear()
	banner()
	if !requireScan() {
		return
	}
	kvTable(sizeHistogram(allRecs(lastResult)))
	pause()
}
func tuiVerify() {
	clear()
	banner()
	if !requireScan() {
		return
	}
	conf, mis := verifyGroups(lastResult)
	okMsg(fmt.Sprintf("byte-verified %d pairs", conf))
	if mis > 0 {
		errMsg(fmt.Sprintf("%d hash collisions detected (bytes differ!)", mis))
	} else {
		okMsg("no hash collisions — all duplicates are byte-identical")
	}
	pause()
}

// ---------------------------------------------------------------------------
// Part 7 — inode/hardlink awareness, detailed group listing, group exports,
// age analysis, and rename suggestions.
// ---------------------------------------------------------------------------

// alreadyLinked reports whether two records are the same on-disk file
// (hardlinked, or a followed symlink), meaning they consume no extra space.
func alreadyLinked(a, b *fileRec) bool { return sameInode(a, b) }

// refineWaste is a group's true reclaimable size; runScan already discounts
// copies that share an inode.
func refineWaste(g dupGroup) int64 { return g.wasted }

func trueReclaimable(res *scanResult) int64 { return res.wasted }

func countAlreadyLinked(res *scanResult) int { return res.linked }

// ---------------------------------------------------------------------------
// Detailed group listing + exports
// ---------------------------------------------------------------------------

func listAllGroups(res *scanResult) string {
	var b strings.Builder
	for i, g := range res.groups {
		b.WriteString(fmt.Sprintf("\nGroup %d  hash=%s  size=%s  copies=%d  wasted=%s\n",
			i+1, truncStr(g.hash, 16), humanBytes(g.size), len(g.files), humanBytes(refineWaste(g))))
		for j, f := range g.files {
			tag := "copy"
			if j == 0 {
				tag = "KEEP"
			}
			linked := ""
			if j > 0 && alreadyLinked(g.files[0], f) {
				linked = " [already hardlinked]"
			}
			b.WriteString(fmt.Sprintf("  [%s] %s  (%s)%s\n", tag, f.path, f.modTime.Format("2006-01-02 15:04"), linked))
		}
	}
	if len(res.groups) == 0 {
		b.WriteString("\n(no duplicate groups)\n")
	}
	return b.String()
}

type groupJSON struct {
	Hash   string   `json:"hash"`
	Size   int64    `json:"size"`
	Wasted int64    `json:"wasted"`
	Files  []string `json:"files"`
}

func exportGroupsJSON(res *scanResult) string {
	var gs []groupJSON
	for _, g := range res.groups {
		var files []string
		for _, f := range g.files {
			files = append(files, f.path)
		}
		gs = append(gs, groupJSON{Hash: g.hash, Size: g.size, Wasted: refineWaste(g), Files: files})
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	_ = enc.Encode(gs)
	return buf.String()
}

func exportGroupsCSV(res *scanResult) string {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	w.Write([]string{"group", "role", "hash", "size", "modified", "path"})
	for i, g := range res.groups {
		for j, f := range g.files {
			role := "copy"
			if j == 0 {
				role = "keep"
			}
			w.Write([]string{strconv.Itoa(i + 1), role, g.hash, strconv.FormatInt(f.size, 10), f.modTime.Format(time.RFC3339), f.path})
		}
	}
	w.Flush()
	return buf.String()
}

// ---------------------------------------------------------------------------
// Age analysis
// ---------------------------------------------------------------------------

func ageAnalysis(res *scanResult) []KV {
	if len(res.groups) == 0 {
		return nil
	}
	var oldest, newest time.Time
	first := true
	var totalAge time.Duration
	count := 0
	for _, g := range res.groups {
		for _, f := range g.files {
			if first {
				oldest, newest = f.modTime, f.modTime
				first = false
			}
			if f.modTime.Before(oldest) {
				oldest = f.modTime
			}
			if f.modTime.After(newest) {
				newest = f.modTime
			}
			totalAge += time.Since(f.modTime)
			count++
		}
	}
	avg := time.Duration(0)
	if count > 0 {
		avg = totalAge / time.Duration(count)
	}
	return []KV{
		{"dup_oldest_mtime", oldest.Format("2006-01-02")},
		{"dup_newest_mtime", newest.Format("2006-01-02")},
		{"dup_span", newest.Sub(oldest).Round(time.Hour).String()},
		{"dup_avg_age_days", strconv.FormatInt(int64(avg.Hours()/24), 10)},
	}
}

// ---------------------------------------------------------------------------
// Rename suggestions (inconsistent naming of identical content)
// ---------------------------------------------------------------------------

func renameSuggestions(res *scanResult) []string {
	var out []string
	for _, g := range res.groups {
		if len(g.files) < 2 {
			continue
		}
		base0 := filepath.Base(g.files[0].path)
		for _, f := range g.files[1:] {
			b := filepath.Base(f.path)
			if b != base0 {
				dist := levenshtein(base0, b)
				if dist > 0 && dist <= maxI(3, len(base0)/3) {
					out = append(out, fmt.Sprintf("'%s' vs '%s' (edit distance %d) — identical content, differing names", base0, b, dist))
				}
			}
		}
		if len(out) >= 30 {
			break
		}
	}
	return out
}

func tuiListGroups() {
	clear()
	banner()
	if !requireScan() {
		return
	}
	fmt.Print(listAllGroups(lastResult))
	pause()
}

func tuiAge() {
	clear()
	banner()
	if !requireScan() {
		return
	}
	kv := ageAnalysis(lastResult)
	if kv == nil {
		okMsg("no duplicates to analyse")
	} else {
		kvTable(kv)
	}
	pause()
}

// ---------------------------------------------------------------------------
// Part 8 — knowledge base of duplicate-prone file types and dedup guidance,
// plus a recommendations engine driven by scan results.
// ---------------------------------------------------------------------------

type dupHint struct {
	ext   string
	kind  string
	note  string
	risky bool
}

var dupProneTypes = []dupHint{
	{".jpg", "photo", "Camera imports and chat apps copy photos repeatedly; safe to hardlink.", false},
	{".jpeg", "photo", "Same as .jpg; watch for re-encoded near-duplicates (use --fuzzy).", false},
	{".png", "image", "Screenshots accumulate exact copies across folders.", false},
	{".heic", "photo", "iOS photo copies; may duplicate alongside converted .jpg.", false},
	{".mp4", "video", "Large videos dominate wasted space; prioritise these groups.", false},
	{".mov", "video", "Phone video copies; very high per-file waste.", false},
	{".zip", "archive", "Downloaded archives re-saved in multiple locations.", false},
	{".tar", "archive", "Backup tarballs commonly duplicated.", false},
	{".gz", "archive", "Compressed logs/backups duplicated by rotation copies.", false},
	{".pdf", "document", "Email attachments saved repeatedly.", false},
	{".docx", "document", "'final', 'final2', 'copy' versions — check --fuzzy.", false},
	{".xlsx", "document", "Spreadsheet copies; verify before deleting (data risk).", true},
	{".iso", "disk-image", "Huge installers; strong hardlink candidates.", false},
	{".vmdk", "vm-disk", "VM disks duplicated by snapshots/clones; verify carefully.", true},
	{".key", "secret", "Private keys MUST NOT be duplicated — consolidate to one copy.", true},
	{".pem", "secret", "Certificates/keys duplicated increase exposure.", true},
	{".env", "secret", "Env files with credentials duplicated across projects.", true},
	{".sql", "database", "DB dumps duplicated by backups; verify before removing.", true},
	{".log", "log", "Rotated/copied logs; often safe but check retention policy.", false},
	{".bak", "backup", "Explicit backup copies — intentional duplication.", true},
}

func hintForExt(ext string) (dupHint, bool) {
	ext = strings.ToLower(ext)
	for _, h := range dupProneTypes {
		if h.ext == ext {
			return h, true
		}
	}
	return dupHint{}, false
}

func printDupReference() {
	fmt.Println("  " + col("Duplicate-prone file types & guidance", CY+B))
	rows := [][]string{}
	for _, h := range dupProneTypes {
		risk := "ok"
		if h.risky {
			risk = "CAUTION"
		}
		rows = append(rows, []string{h.ext, h.kind, risk, truncStr(h.note, 44)})
	}
	table([]string{"EXT", "KIND", "RISK", "NOTE"}, rows)
}

// recommendations builds an ordered action list from a scan result.
func recommendations(res *scanResult) []string {
	var recs []string
	if len(res.groups) == 0 {
		return []string{"No exact duplicates found — nothing to reclaim."}
	}
	recs = append(recs, fmt.Sprintf("Start with the largest groups: the top group alone wastes %s.", humanBytes(res.groups[0].wasted)))
	if res.linked > 0 {
		recs = append(recs, fmt.Sprintf("%d copies already share storage (hardlinks) and were excluded from the reclaimable total.", res.linked))
	}
	risky := false
	for _, g := range res.groups {
		if h, ok := hintForExt(filepath.Ext(g.files[0].path)); ok && h.risky {
			risky = true
			break
		}
	}
	if risky {
		recs = append(recs, "CAUTION: some duplicates are secrets/databases/VM disks — verify and back up before removing.")
	}
	recs = append(recs, "Prefer --plan hardlink over delete: it reclaims space while keeping every path working.")
	recs = append(recs, "Always export a --script and review it before executing any destructive action.")
	recs = append(recs, "Re-run with --verify to confirm byte-identity and rule out hash collisions.")
	return recs
}

func tuiReference() {
	clear()
	banner()
	printDupReference()
	fmt.Println()
	if lastResult != nil {
		fmt.Println("  " + col("Recommendations", CY+B))
		for _, r := range recommendations(lastResult) {
			info(r)
		}
	}
	pause()
}

var moreDupTypes = []dupHint{
	{".gif", "image", "Meme/animation copies spread across chat exports.", false},
	{".webp", "image", "Browser-saved images; near-dupes of jpg/png.", false},
	{".raw", "photo", "Camera RAW originals; very large, high waste.", false},
	{".cr2", "photo", "Canon RAW; duplicated by import tools.", false},
	{".nef", "photo", "Nikon RAW; duplicated by import tools.", false},
	{".mkv", "video", "Media library duplicates; huge per-file waste.", false},
	{".avi", "video", "Legacy video copies.", false},
	{".flac", "audio", "Lossless audio duplicated across libraries.", false},
	{".mp3", "audio", "Music libraries re-import the same tracks.", false},
	{".wav", "audio", "Uncompressed audio; large duplicates.", false},
	{".7z", "archive", "Compressed archives duplicated on download.", false},
	{".rar", "archive", "Archive copies; verify contents before removing.", false},
	{".pptx", "document", "Presentation 'final' copies; use --fuzzy.", false},
	{".csv", "data", "Dataset snapshots duplicated across analyses.", true},
	{".json", "data", "Config/data snapshots duplicated across projects.", false},
	{".kdbx", "secret", "Password databases MUST stay single-copy.", true},
	{".ovpn", "secret", "VPN profiles with embedded keys duplicated.", true},
}

func allDupHints() []dupHint { return append(append([]dupHint{}, dupProneTypes...), moreDupTypes...) }

// wastedByKind aggregates reclaimable bytes by high-level file kind.
func wastedByKind(res *scanResult) []KV {
	kindOf := map[string]string{}
	for _, h := range allDupHints() {
		kindOf[h.ext] = h.kind
	}
	agg := map[string]int64{}
	for _, g := range res.groups {
		ext := strings.ToLower(filepath.Ext(g.files[0].path))
		kind := kindOf[ext]
		if kind == "" {
			kind = "other"
		}
		agg[kind] += refineWaste(g)
	}
	type kw struct {
		k string
		v int64
	}
	var list []kw
	for k, v := range agg {
		list = append(list, kw{k, v})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].v > list[j].v })
	var out []KV
	for _, x := range list {
		out = append(out, KV{x.k, humanBytes(x.v)})
	}
	return out
}

// dedupHealthCard prints a compact posture summary.
func dedupHealthCard(res *scanResult) {
	rep := buildReport(res)
	rep.finalize()
	fmt.Println("  " + col("De-duplication health card", CY+B))
	fmt.Println()
	info("root            : " + res.cfg.root)
	info("files scanned   : " + commaInt(int64(res.total)))
	info("duplicate groups: " + commaInt(int64(len(res.groups))))
	info("reclaimable     : " + humanBytes(trueReclaimable(res)))
	info(fmt.Sprintf("posture grade   : %s (%.1f/100)", rep.Grade, rep.Score))
	fmt.Println()
	if wk := wastedByKind(res); len(wk) > 0 {
		fmt.Println("  " + col("waste by kind", CY+B))
		kvTable(wk)
	}
}

func tuiHealth() {
	clear()
	banner()
	if !requireScan() {
		return
	}
	dedupHealthCard(lastResult)
	pause()
}

// kindDistribution returns the number of duplicate groups per file kind.
func kindDistribution(res *scanResult) map[string]int {
	kindOf := map[string]string{}
	for _, h := range allDupHints() {
		kindOf[h.ext] = h.kind
	}
	out := map[string]int{}
	for _, g := range res.groups {
		ext := strings.ToLower(filepath.Ext(g.files[0].path))
		k := kindOf[ext]
		if k == "" {
			k = "other"
		}
		out[k]++
	}
	return out
}

// ---------------------------------------------------------------------------
// Help & Usage  (interactive menu [H])
// Page 1: in-app guide (what the tool does, every menu option, tips).
// Page 2: the full command-line reference (same text as --help).
// ---------------------------------------------------------------------------

type owlHelpItem struct{ key, text string }

func owlHelpWrap(s string, width int) []string {
	var out []string
	for _, para := range strings.Split(s, "\n") {
		words := strings.Fields(para)
		if len(words) == 0 {
			out = append(out, "")
			continue
		}
		cur := ""
		for _, w := range words {
			if cur != "" && len([]rune(cur))+1+len([]rune(w)) > width {
				out = append(out, cur)
				cur = w
			} else if cur == "" {
				cur = w
			} else {
				cur += " " + w
			}
		}
		out = append(out, cur)
	}
	return out
}

func owlHelpTitle(t string) {
	fmt.Println()
	fmt.Println("  " + col("▸ "+t, B+CY))
}

func owlHelpPara(lines []string) {
	for _, l := range lines {
		for _, w := range owlHelpWrap(l, 60) {
			fmt.Println("    " + col(w, W))
		}
	}
}

func owlHelpRows(items []owlHelpItem) {
	kw := 0
	for _, it := range items {
		if n := len([]rune(it.key)); n > kw {
			kw = n
		}
	}
	for _, it := range items {
		k := "[" + it.key + "]" + strings.Repeat(" ", kw-len([]rune(it.key)))
		for i, w := range owlHelpWrap(it.text, 56-kw) {
			if i == 0 {
				fmt.Println("    " + col(k, YLW+B) + "  " + col(w, W))
			} else {
				fmt.Println("    " + strings.Repeat(" ", kw+2) + "  " + col(w, W))
			}
		}
	}
}

func owlHelpRule() { fmt.Println(col(strings.Repeat("─", 66), CY)) }

func tuiHelp() {
	clear()
	banner()
	owlHelpRule()
	fmt.Println("  " + col("⬡  Help & Usage — "+APPNAME, B+CY))
	owlHelpRule()
	owlHelpTitle("WHAT IT DOES")
	owlHelpPara(owlHelpAbout)
	owlHelpTitle("HOW TO USE THE MENU")
	owlHelpPara(owlHelpFlow)
	owlHelpTitle("MENU OPTIONS")
	owlHelpRows(owlHelpMenu)
	owlHelpTitle("TIPS")
	owlHelpRows(owlHelpTips)
	fmt.Println()
	owlHelpRule()
	fmt.Println("  " + col("Next page: command-line flags & copy-paste examples", DIM))
	pause()
	clear()
	owlHelpCLI()
	fmt.Println()
	fmt.Println("  " + col("Tip: the same reference is printed by  "+APPNAME+" --help", DIM))
	pause()
}

var owlHelpAbout = []string{
	"ODedupe finds duplicate files. Files are compared by size first, then by a quick hash of the first bytes, then by a full hash (sha256 by default), so large trees are scanned fast and only real copies are reported. It shows how much space you can reclaim, where the waste is (folders, file types, sizes, ages), finds whole duplicated directories and near-duplicates with similar names and sizes.",
	"ODedupe is read-only. It never deletes, moves or links anything. Clean-up is only planned: you get a preview or a shell script that you review and run yourself.",
}

var owlHelpFlow = []string{
	"Type the number of an option (1 or 01) and press Enter. Always start with [01] Scan a directory. Every other option works on the result of that scan. [H] opens this help, [0] or q quits.",
	"Sizes can be written as 512, 4K, 1.5M, 2G or 1T.",
}

var owlHelpMenu = []owlHelpItem{
	{"01", "Scan a directory: enter the folder to scan, a minimum file size (blank = 1 byte), the hash (sha256 / sha1 / md5, blank = sha256) and names to skip as a comma list (e.g. node_modules,.git,*.tmp). Prints a summary of duplicate groups and reclaimable space."},
	{"02", "Fuzzy near-duplicate scan: enter a similarity threshold from 0 to 1 (blank = 0.75). Lists pairs of files with similar names and sizes that are not exact copies, such as report.pdf and report (1).pdf."},
	{"03", "Top waste groups: the duplicate groups that waste the most space."},
	{"04", "Build action plan (dry-run): choose delete, hardlink or move and which copy to keep (keep-oldest / keep-newest / keep-shortest-path). Shows what would happen; nothing is changed."},
	{"05", "Write reviewable plan script: choose the operation and a file name for the script (e.g. plan.sh). Every command in it re-checks with cmp that the files are still identical. Read it before you run it."},
	{"06", "Export last report: choose txt, md, json, csv or sarif and an output file (blank = print to screen)."},
	{"07", "Extension statistics: duplicate space per file type (jpg, mp4, zip ...)."},
	{"08", "Directory hot-spots: the folders that hold the most duplicate data."},
	{"09", "Duplicate directories: whole folders whose contents are identical."},
	{"10", "Size histogram: how many duplicates fall into each size range."},
	{"11", "Byte-exact verify: compares the duplicates byte by byte to rule out hash collisions."},
	{"12", "List all groups: every group, showing the copy that is kept and its duplicates."},
	{"13", "Age analysis: how old the duplicate copies are (modification-time spread)."},
	{"14", "Health card: an overall grade, reclaimable bytes and waste by file kind."},
	{"15", "File-type reference & advice: which file types are usually duplicated and how to handle them."},
	{"16", "Self-test: runs the built-in correctness checks."},
}

var owlHelpTips = []owlHelpItem{
	{"*", "hardlink keeps every path working but stores the data once. It is the safest way to reclaim space on the same disk."},
	{"*", "On the command line, --prefer PREFIX always keeps the copy under a folder you choose, e.g. --prefer /data/originals."},
	{"*", "--manifest FILE saves a snapshot and --baseline FILE later shows what changed since then."},
}

func owlHelpCLI() { usage() }
