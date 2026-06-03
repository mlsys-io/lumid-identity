package handler

// Document text extraction for chat attachments. Each extractor takes
// a base64-encoded payload and returns the plaintext content.
//
// Tooling (all installed in the identity Dockerfile):
//   pdftotext  (poppler-utils)  → PDF
//   pandoc                       → docx, rtf, odt, epub, html
//   python3 + py3-openpyxl       → xlsx
//
// pptx goes through pandoc, which extracts the slide text content.
// xls (the legacy binary format) is NOT supported — users with .xls
// files should re-save as .xlsx (Excel does this automatically).

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

const (
	docExtractTimeout = 30 * time.Second
	docMaxOutput      = 256 * 1024 // 256 KB extracted text ceiling
)

// extractDocumentText dispatches by mime to the right extractor.
// Returns (text, extractor-name, error). extractor-name is surfaced
// in the message ("extracted via pdftotext") so the LLM (+ debugging
// humans) know which transformation produced the content.
func extractDocumentText(mime, base64Data string) (string, string, error) {
	switch normaliseMime(mime) {
	case "application/pdf":
		// pdftotext defaults to writing a sibling .txt file when no
		// output path is given — pass "-" to send stdout instead.
		out, err := runOnTemp(base64Data, ".pdf", "pdftotext", []string{"-layout", "{TEMP}", "-"}, true)
		return out, "pdftotext", err

	case "application/vnd.openxmlformats-officedocument.wordprocessingml.document":
		out, err := pandocExtract(base64Data, ".docx")
		return out, "pandoc (docx)", err

	case "application/vnd.openxmlformats-officedocument.presentationml.presentation":
		out, err := pandocExtract(base64Data, ".pptx")
		return out, "pandoc (pptx)", err

	case "application/rtf", "text/rtf":
		out, err := pandocExtract(base64Data, ".rtf")
		return out, "pandoc (rtf)", err

	case "application/vnd.oasis.opendocument.text":
		out, err := pandocExtract(base64Data, ".odt")
		return out, "pandoc (odt)", err

	case "application/vnd.oasis.opendocument.spreadsheet":
		out, err := pandocExtract(base64Data, ".ods")
		return out, "pandoc (ods)", err

	case "application/vnd.oasis.opendocument.presentation":
		out, err := pandocExtract(base64Data, ".odp")
		return out, "pandoc (odp)", err

	case "application/epub+zip":
		out, err := pandocExtract(base64Data, ".epub")
		return out, "pandoc (epub)", err

	case "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet":
		out, err := xlsxExtract(base64Data)
		return out, "openpyxl", err
	}
	return "", "", fmt.Errorf("unsupported document mime: %s (supported: pdf, docx, xlsx, pptx, rtf, odt, ods, odp, epub)", mime)
}

// normaliseMime trims params like "; charset=..." and lowercases.
func normaliseMime(m string) string {
	if i := strings.Index(m, ";"); i >= 0 {
		m = m[:i]
	}
	return strings.ToLower(strings.TrimSpace(m))
}

// pdftotextExtract — used by the older pdf code path; kept for back-
// compat with chatMessageToAnthropic call sites that bypassed the
// generic dispatcher.
func pdftotextExtract(base64Data string) (string, error) {
	out, _, err := extractDocumentText("application/pdf", base64Data)
	return out, err
}

// pandocExtract decodes the base64 payload to a temp file with the
// given extension, runs `pandoc -t plain <file>`, returns stdout.
func pandocExtract(base64Data, ext string) (string, error) {
	return runOnTemp(base64Data, ext, "pandoc", []string{"-t", "plain"}, true)
}

// xlsxExtract shells out to a small inline Python script using
// openpyxl. Returns one section per non-empty sheet with cells joined
// by `\t`, rows by `\n`, sheets separated by `## Sheet: <name>` headers.
func xlsxExtract(base64Data string) (string, error) {
	const script = `
import sys, openpyxl
wb = openpyxl.load_workbook(sys.argv[1], data_only=True, read_only=True)
out = []
for ws in wb.worksheets:
    rows = []
    for row in ws.iter_rows(values_only=True):
        cells = [("" if v is None else str(v)) for v in row]
        if any(c.strip() for c in cells):
            rows.append("\t".join(cells))
    if not rows:
        continue
    out.append("## Sheet: " + ws.title)
    out.extend(rows)
    out.append("")
sys.stdout.write("\n".join(out))
`
	return runOnTemp(base64Data, ".xlsx", "python3", []string{"-c", script, "{TEMP}"}, true)
}

// runOnTemp decodes the base64 payload to a temp file in $TMPDIR,
// runs `tool [args...] <tempfile>` (or substitutes "{TEMP}" anywhere
// in args), captures stdout, and removes the temp file. Returns the
// stdout (capped at docMaxOutput) on success.
func runOnTemp(base64Data, ext, tool string, args []string, _ bool) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(base64Data)
	if err != nil {
		return "", fmt.Errorf("base64: %w", err)
	}

	f, err := os.CreateTemp("", "chatdoc-*"+ext)
	if err != nil {
		return "", fmt.Errorf("tempfile: %w", err)
	}
	tempPath := f.Name()
	defer os.Remove(tempPath)
	if _, err := f.Write(raw); err != nil {
		f.Close()
		return "", fmt.Errorf("write: %w", err)
	}
	f.Close()

	// Substitute {TEMP} placeholder or append at the end.
	finalArgs := make([]string, 0, len(args)+1)
	substituted := false
	for _, a := range args {
		if a == "{TEMP}" {
			finalArgs = append(finalArgs, tempPath)
			substituted = true
		} else {
			finalArgs = append(finalArgs, a)
		}
	}
	if !substituted {
		finalArgs = append(finalArgs, tempPath)
	}

	ctx, cancel := context.WithTimeout(context.Background(), docExtractTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, tool, finalArgs...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		excerpt := stderr.String()
		if len(excerpt) > 200 {
			excerpt = excerpt[:200]
		}
		return "", fmt.Errorf("%s: %v (%s)", tool, err, excerpt)
	}

	out := stdout.String()
	if len(out) > docMaxOutput {
		out = out[:docMaxOutput] + "\n…(truncated at " + fmt.Sprintf("%d", docMaxOutput) + " bytes)"
	}
	return strings.TrimSpace(out), nil
}
