package main

import (
	"path/filepath"
	"sort"
	"strings"
)

func parseYARA(output string, knowledge Knowledge) []Finding {
	findings := make(map[string]*Finding)
	currentRule := ""
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		rule := parts[0]
		if strings.HasPrefix(rule, "0x") {
			if currentRule == "" || len(parts) == 0 {
				continue
			}
			rule = currentRule
		} else {
			currentRule = rule
			if len(parts) == 1 {
				continue
			}
		}
		finding, ok := findings[rule]
		if !ok {
			finding = &Finding{Rule: rule}
			if info, exists := knowledge.Rules[rule]; exists {
				finding.Library, finding.Algorithm = info.Library, info.Algorithm
			}
			findings[rule] = finding
		}
		if strings.HasPrefix(parts[0], "0x") && len(parts) > 1 {
			finding.Evidence = appendUniqueEvidence(finding.Evidence, Evidence{Type: "yara_match", Value: parts[len(parts)-1], Strength: "medium"})
		}
	}
	result := make([]Finding, 0, len(findings))
	for _, finding := range findings {
		sort.Slice(finding.Evidence, func(i, j int) bool { return finding.Evidence[i].Value < finding.Evidence[j].Value })
		result = append(result, *finding)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Rule < result[j].Rule })
	return result
}

func appendUnique(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func appendUniqueEvidence(values []Evidence, value Evidence) []Evidence {
	for _, existing := range values {
		if existing.Type == value.Type && existing.Value == value.Value {
			return values
		}
	}
	return append(values, value)
}

func mergeLIEFFindings(findings []Finding, imports []string, knowledge Knowledge) []Finding {
	byRule := make(map[string]int, len(findings))
	for i := range findings {
		byRule[findings[i].Rule] = i
	}
	for rule, info := range knowledge.Rules {
		matched := make([]string, 0, len(info.Imports))
		for _, marker := range info.Imports {
			for _, imported := range imports {
				if strings.TrimPrefix(imported, "_") == strings.TrimPrefix(marker, "_") {
					matched = appendUnique(matched, imported)
					break
				}
			}
		}
		required := info.RequiredEvidence
		if required <= 0 {
			required = 1
		}
		if len(matched) < required {
			continue
		}
		findingIndex, ok := byRule[rule]
		if !ok {
			findings = append(findings, Finding{Rule: rule, Library: info.Library, Algorithm: info.Algorithm})
			findingIndex = len(findings) - 1
			byRule[rule] = findingIndex
		}
		finding := &findings[findingIndex]
		finding.Library, finding.Algorithm = info.Library, info.Algorithm
		for _, imported := range matched {
			finding.Evidence = appendUniqueEvidence(finding.Evidence, Evidence{Type: "lief_import", Value: imported, Strength: "high"})
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Rule < findings[j].Rule })
	return findings
}

func findUnrecognizedImports(imports []string, knowledge Knowledge) []string {
	known := make(map[string]bool)
	for _, info := range knowledge.Rules {
		for _, marker := range info.Imports {
			known[strings.TrimPrefix(marker, "_")] = true
		}
	}
	var result []string
	for _, imported := range imports {
		normalized := strings.TrimPrefix(imported, "_")
		if known[normalized] || !looksCryptographic(normalized) {
			continue
		}
		result = appendUnique(result, imported)
	}
	sort.Strings(result)
	return result
}

func looksCryptographic(name string) bool {
	upper := strings.ToUpper(name)
	markers := []string{"SHA", "HMAC", "AES_", "AES-", "CHACHA", "POLY1305", "BLAKE", "CURVE25519", "X25519", "ED25519", "ECDSA", "RSA", "HKDF", "PBKDF", "ML-KEM", "MLKEM", "ML-DSA", "MLDSA", "SLH-DSA", "SLHDSA", "SCRYPT", "DES", "GCM", "CBC"}
	for _, marker := range markers {
		if strings.Contains(upper, marker) {
			return true
		}
	}
	return false
}

func findAlgorithmHints(data []byte) []string {
	var hints []string
	current := make([]byte, 0, 64)
	flush := func() {
		if len(current) >= 4 {
			candidate := string(current)
			lower := strings.ToLower(candidate)
			if !strings.HasPrefix(candidate, "_") && !strings.Contains(lower, "target") && !strings.Contains(lower, "test") && looksCryptographic(candidate) {
				hints = appendUnique(hints, candidate)
			}
		}
		current = current[:0]
	}
	for _, b := range data {
		if b >= 32 && b <= 126 {
			current = append(current, b)
		} else {
			flush()
		}
	}
	flush()
	sort.Strings(hints)
	return hints
}

func normalizeDependencies(libraries []string) []string {
	var result []string
	for _, library := range libraries {
		base := strings.ToLower(filepath.Base(library))
		if strings.Contains(base, "libsystem") {
			continue
		}
		dependency := library
		switch {
		case strings.Contains(base, "libcrypto"):
			dependency = "OpenSSL libcrypto"
		case strings.Contains(base, "libssl"):
			dependency = "OpenSSL libssl"
		}
		result = appendUnique(result, dependency)
	}
	sort.Strings(result)
	return result
}

func apiFromEvidence(evidence []Evidence) string {
	for _, item := range evidence {
		value := item.Value
		if item.Type == "lief_import" || strings.Contains(value, "EVP_") || strings.HasPrefix(value, "SHA") || strings.HasPrefix(value, "RSA_") || strings.HasPrefix(value, "ECDSA_") {
			return value
		}
	}
	if len(evidence) > 0 {
		return evidence[0].Value
	}
	return ""
}
