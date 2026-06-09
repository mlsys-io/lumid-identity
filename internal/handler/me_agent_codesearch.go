package handler

// me_agent tools: glob_files, grep_files, multi_edit.
//
// Code-navigation + multi-spot editing for the chat agent — the pieces
// Claude Code has (Glob/Grep + MultiEdit) that the in-house loop lacked.
// All three are JAILED exactly like the other file tools:
//   - reads (glob_files, grep_files) → readRoot(userID, role)
//   - writes (multi_edit)            → writeRoot(userID, role)
// so scope follows identity (a regular user sees only their own tenant
// workspace; super_admin sees /proj). Capability is universal; the jail,
// not the role, bounds what each caller can reach.

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// skipDirNames — directories never worth walking for glob/grep (noise +
// performance). Skipped unless they ARE the jail root itself.
var skipDirNames = map[string]bool{
	".git": true, "node_modules": true, ".venv": true, "venv": true,
	"__pycache__": true, "dist": true, "build": true, ".next": true,
	"target": true, ".cache": true, "vendor": true, ".mypy_cache": true,
}

// globMatch matches a workspace-relative path against a glob pattern with
// limited "**" support: a leading "**/" means "in any directory", a pattern
// with no "/" matches the basename, otherwise filepath.Match on the relpath.
func globMatch(pattern, rel string) bool {
	pattern = strings.TrimSpace(pattern)
	switch pattern {
	case "", "*", "**", "**/*":
		return true
	}
	if strings.HasPrefix(pattern, "**/") {
		sub := pattern[3:]
		if ok, _ := filepath.Match(sub, filepath.Base(rel)); ok {
			return true
		}
		ok, _ := filepath.Match(sub, rel)
		return ok
	}
	if !strings.Contains(pattern, "/") {
		ok, _ := filepath.Match(pattern, filepath.Base(rel))
		return ok
	}
	ok, _ := filepath.Match(pattern, rel)
	return ok
}

// toolGlobFiles finds files whose workspace-relative path matches pattern.
func toolGlobFiles(userID, role, pattern string, maxResults int) (map[string]any, bool) {
	if maxResults <= 0 || maxResults > 1000 {
		maxResults = 300
	}
	root := readRoot(userID, role)
	var hits []string
	truncated := false
	_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if p != root && skipDirNames[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil {
			return nil
		}
		if globMatch(pattern, rel) {
			if len(hits) >= maxResults {
				truncated = true
				return filepath.SkipAll
			}
			hits = append(hits, rel)
		}
		return nil
	})
	return map[string]any{"files": hits, "count": len(hits), "truncated": truncated}, true
}

// toolGrepFiles searches file CONTENTS for a regex within the read jail,
// optionally restricted to files matching path_glob. Returns matching lines
// as {path, line, text}.
func toolGrepFiles(userID, role, pattern, pathGlob string, maxResults int) (map[string]any, bool) {
	if maxResults <= 0 || maxResults > 500 {
		maxResults = 100
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return map[string]any{"error": "bad regex: " + err.Error()}, false
	}
	root := readRoot(userID, role)
	type match struct {
		Path string `json:"path"`
		Line int    `json:"line"`
		Text string `json:"text"`
	}
	matches := []match{}
	truncated := false
	const maxFileScan = 2 * 1024 * 1024 // skip files larger than 2 MB
	_ = filepath.WalkDir(root, func(p string, d os.DirEntry, werr error) error {
		if werr != nil {
			return nil
		}
		if d.IsDir() {
			if p != root && skipDirNames[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if pathGlob != "" {
			rel, rerr := filepath.Rel(root, p)
			if rerr != nil || !globMatch(pathGlob, rel) {
				return nil
			}
		}
		info, ierr := d.Info()
		if ierr != nil || info.Size() > maxFileScan {
			return nil
		}
		data, derr := os.ReadFile(p)
		if derr != nil {
			return nil
		}
		if bytes.IndexByte(data, 0) >= 0 {
			return nil // binary file
		}
		rel, _ := filepath.Rel(root, p)
		sc := bufio.NewScanner(bytes.NewReader(data))
		sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		ln := 0
		for sc.Scan() {
			ln++
			line := sc.Text()
			if !re.MatchString(line) {
				continue
			}
			if len(matches) >= maxResults {
				truncated = true
				return filepath.SkipAll
			}
			line = strings.TrimSpace(line)
			if len(line) > 300 {
				line = line[:300] + "…"
			}
			matches = append(matches, match{Path: rel, Line: ln, Text: line})
		}
		return nil
	})
	return map[string]any{"matches": matches, "count": len(matches), "truncated": truncated}, true
}

// editOp is one find/replace within multi_edit.
type editOp struct {
	OldString  string
	NewString  string
	ReplaceAll bool
}

// toolMultiEdit applies a sequence of edits to ONE file atomically: every
// old_string must be found (validated in-memory) before anything is written.
// If any edit fails to match, the file is left untouched.
func toolMultiEdit(userID, role, rawPath string, edits []editOp) (map[string]any, bool) {
	if len(edits) == 0 {
		return map[string]any{"error": "edits required"}, false
	}
	root := writeRoot(userID, role)
	abs, err := jailPath(root, rawPath)
	if err != nil {
		return map[string]any{"error": err.Error()}, false
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		return map[string]any{"error": err.Error()}, false
	}
	content := string(data)
	for i, e := range edits {
		if e.OldString == "" {
			return map[string]any{"error": fmt.Sprintf("edit %d: old_string required", i)}, false
		}
		if !strings.Contains(content, e.OldString) {
			return map[string]any{"error": fmt.Sprintf("edit %d: old_string not found in file", i)}, false
		}
		if e.ReplaceAll {
			content = strings.ReplaceAll(content, e.OldString, e.NewString)
		} else {
			content = strings.Replace(content, e.OldString, e.NewString, 1)
		}
	}
	if err := checkDiskQuota(root, int64(len(content))); err != nil {
		return map[string]any{"error": err.Error()}, false
	}
	if err := os.WriteFile(abs, []byte(content), 0o644); err != nil {
		return map[string]any{"error": err.Error()}, false
	}
	return map[string]any{"ok": true, "path": abs, "edits_applied": len(edits), "bytes": len(content)}, true
}
