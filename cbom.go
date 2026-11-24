package main

import (
	"sort"
	"strings"
)

func buildCBOM(findings []Finding, unknownImports, hints, symbols []string, knowledge Knowledge) ([]CBOMAsset, []CBOMCandidate) {
	var assets []CBOMAsset
	seenAssets := make(map[string]bool)
	confirmedAlgorithms := make(map[string]bool)
	for _, finding := range findings {
		if finding.Algorithm == "" {
			continue
		}
		info := knowledge.Rules[finding.Rule]
		api := apiFromEvidence(finding.Evidence)
		confidence := "medium"
		for _, evidence := range finding.Evidence {
			if evidence.Type == "lief_import" {
				api = evidence.Value
				confidence = "high"
				break
			}
		}
		asset := CBOMAsset{
			Algorithm:  finding.Algorithm,
			Purpose:    purposeFor(info, finding.Algorithm),
			Source:     "binary",
			API:        strings.TrimPrefix(api, "LIEF:"),
			Evidence:   finding.Evidence,
			Confidence: confidence,
			Mapping:    info.Status,
		}
		key := asset.Algorithm + "\x00" + asset.API
		if !seenAssets[key] {
			assets = append(assets, asset)
			seenAssets[key] = true
		}
		confirmedAlgorithms[asset.Algorithm] = true
	}
	for _, symbolFinding := range symbolFindings(symbols, knowledge) {
		if confirmedAlgorithms[symbolFinding.Algorithm] {
			continue
		}
		asset := CBOMAsset{
			Algorithm:  symbolFinding.Algorithm,
			Purpose:    purposeFor(KnowledgeRule{}, symbolFinding.Algorithm),
			Source:     "binary-symbol",
			API:        symbolFinding.API,
			Evidence:   symbolFinding.Evidence,
			Confidence: "medium",
			Mapping:    "symbol-derived",
		}
		key := asset.Algorithm + "\x00" + asset.API
		if !seenAssets[key] {
			assets = append(assets, asset)
			seenAssets[key] = true
			confirmedAlgorithms[asset.Algorithm] = true
		}
	}
	assets = refineAssets(assets, symbols, unknownImports)
	assets = consolidateAssets(assets)
	confirmedAlgorithms = make(map[string]bool)
	for _, asset := range assets {
		confirmedAlgorithms[asset.Algorithm] = true
	}

	var candidates []CBOMCandidate
	seenCandidates := make(map[string]bool)
	for _, imported := range unknownImports {
		candidate := CBOMCandidate{
			Algorithm:  algorithmFromImport(imported, knowledge),
			API:        imported,
			Evidence:   []Evidence{{Type: "lief_import", Value: imported, Strength: "medium"}},
			Confidence: "candidate",
		}
		if candidate.Algorithm != "" && !confirmedAlgorithms[candidate.Algorithm] {
			appendCandidate(&candidates, seenCandidates, candidate)
		}
	}
	for _, hint := range hints {
		for _, algorithm := range algorithmsFromHint(hint, knowledge) {
			candidate := CBOMCandidate{Algorithm: algorithm, Evidence: []Evidence{{Type: "string_hint", Value: hint, Strength: "low"}}, Confidence: "candidate"}
			if !confirmedAlgorithms[candidate.Algorithm] {
				appendCandidate(&candidates, seenCandidates, candidate)
			}
		}
	}
	sort.Slice(assets, func(i, j int) bool { return assets[i].Algorithm < assets[j].Algorithm })
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].Algorithm == candidates[j].Algorithm {
			return candidates[i].API < candidates[j].API
		}
		return candidates[i].Algorithm < candidates[j].Algorithm
	})
	return assets, candidates
}

// refineAssets combines evidence that is only meaningful together and removes
// implementation/platform markers that are not algorithms themselves.
func refineAssets(assets []CBOMAsset, symbols, imports []string) []CBOMAsset {
	has := func(algorithm string) bool {
		for _, asset := range assets {
			if asset.Algorithm == algorithm {
				return true
			}
		}
		return false
	}
	hasSymbol := func(marker string) bool {
		marker = strings.ToUpper(marker)
		for _, symbol := range symbols {
			if strings.Contains(strings.ToUpper(symbol), marker) {
				return true
			}
		}
		return false
	}
	hasEvidence := func(marker string) bool {
		marker = strings.ToUpper(marker)
		for _, asset := range assets {
			if strings.Contains(strings.ToUpper(asset.API), marker) {
				return true
			}
			for _, evidence := range asset.Evidence {
				if strings.Contains(strings.ToUpper(evidence.Value), marker) {
					return true
				}
			}
		}
		for _, imported := range imports {
			if strings.Contains(strings.ToUpper(imported), marker) {
				return true
			}
		}
		return false
	}

	refined := make([]CBOMAsset, 0, len(assets))
	for _, asset := range assets {
		if asset.Algorithm == "SHA-2" && (has("SHA-256") || has("SHA-512")) {
			continue
		}
		if asset.Algorithm == "AES" && hasSymbol("CBC") {
			asset.Algorithm = "AES-CBC"
			asset.Purpose = "encryption"
		}
		if asset.Algorithm == "HMAC" && has("SHA-512") {
			asset.Algorithm = "HMAC-SHA512"
			asset.Purpose = "message authentication"
		}
		if asset.Algorithm == "RSA" && has("SHA-256") && (hasSymbol("SignPSS") || hasEvidence("PKEY_CTX_SET_RSA_PADDING") || hasEvidence("RSA-PSS")) {
			asset.Algorithm = "RSA-PSS-SHA256"
			asset.Purpose = "signature"
		}
		if asset.Algorithm == "ECDSA" && (hasEvidence("P256") || hasEvidence("PRIME256V1")) {
			asset.Algorithm = "ECDSA P-256"
			asset.Purpose = "signature"
		}
		refined = append(refined, asset)
	}
	return refined
}

func consolidateAssets(assets []CBOMAsset) []CBOMAsset {
	hasSpecific := make(map[string]bool)
	for _, asset := range assets {
		switch asset.Algorithm {
		case "AES-128-CBC", "AES-256-CBC", "AES-256-GCM", "ECDSA P-256", "RSA-PSS-SHA256":
			hasSpecific[asset.Algorithm] = true
		}
	}
	byAlgorithm := make(map[string]int)
	result := make([]CBOMAsset, 0, len(assets))
	for _, asset := range assets {
		if asset.Algorithm == "AES-CBC" && (hasSpecific["AES-128-CBC"] || hasSpecific["AES-256-CBC"]) {
			continue
		}
		if asset.Algorithm == "ECDSA" && hasSpecific["ECDSA P-256"] {
			continue
		}
		if asset.Algorithm == "RSA" && hasSpecific["RSA-PSS-SHA256"] {
			continue
		}
		if index, ok := byAlgorithm[asset.Algorithm]; ok {
			result[index].Evidence = appendUniqueEvidenceList(result[index].Evidence, asset.Evidence)
			if result[index].Confidence != "high" && asset.Confidence == "high" {
				result[index].Confidence = "high"
			}
			continue
		}
		byAlgorithm[asset.Algorithm] = len(result)
		result = append(result, asset)
	}
	return result
}

func appendUniqueEvidenceList(existing []Evidence, additions []Evidence) []Evidence {
	for _, addition := range additions {
		existing = appendUniqueEvidence(existing, addition)
	}
	return existing
}

type symbolFinding struct {
	Algorithm string
	API       string
	Evidence  []Evidence
}

func symbolFindings(symbols []string, knowledge Knowledge) []symbolFinding {
	type grouped struct {
		algorithm string
		values    []string
	}
	groups := make(map[string]*grouped)
	for _, symbol := range symbols {
		algorithm := algorithmFromKnowledgeSymbol(symbol, knowledge)
		if algorithm == "" {
			continue
		}
		group := groups[algorithm]
		if group == nil {
			group = &grouped{algorithm: algorithm}
			groups[algorithm] = group
		}
		if len(group.values) < 3 {
			group.values = appendUnique(group.values, symbol)
		}
	}
	result := make([]symbolFinding, 0, len(groups))
	for _, group := range groups {
		if len(group.values) == 0 {
			continue
		}
		evidence := make([]Evidence, 0, len(group.values))
		for _, value := range group.values {
			evidence = append(evidence, Evidence{Type: "symbol", Value: value, Strength: "medium"})
		}
		result = append(result, symbolFinding{Algorithm: group.algorithm, API: group.values[0], Evidence: evidence})
	}
	result = filterGenericPQCFindings(result)
	sort.Slice(result, func(i, j int) bool { return result[i].Algorithm < result[j].Algorithm })
	return result
}

func algorithmFromKnowledgeSymbol(symbol string, knowledge Knowledge) string {
	upper := strings.ToUpper(symbol)
	if algorithm := algorithmFromSymbol(symbol); algorithm != "" {
		return algorithm
	}
	for _, rule := range knowledge.Rules {
		for _, marker := range rule.Symbols {
			if marker != "" && strings.Contains(upper, strings.ToUpper(marker)) {
				return rule.Algorithm
			}
		}
	}
	return algorithmFromSymbol(symbol)
}

func filterGenericPQCFindings(findings []symbolFinding) []symbolFinding {
	specific := make(map[string]bool)
	for _, finding := range findings {
		if strings.HasPrefix(finding.Algorithm, "ML-KEM-") || strings.HasPrefix(finding.Algorithm, "ML-DSA-") {
			specific[strings.Split(finding.Algorithm, "-")[0]+"-"+strings.Split(finding.Algorithm, "-")[1]] = true
		}
	}
	filtered := make([]symbolFinding, 0, len(findings))
	for _, finding := range findings {
		if (finding.Algorithm == "ML-KEM" && specific["ML-KEM"]) || (finding.Algorithm == "ML-DSA" && specific["ML-DSA"]) {
			continue
		}
		filtered = append(filtered, finding)
	}
	return filtered
}

func algorithmFromSymbol(symbol string) string {
	upper := strings.ToUpper(symbol)
	switch {
	case strings.Contains(upper, "ML_KEM") || strings.Contains(upper, "MLKEM"):
		for _, marker := range []struct {
			marker string
			level  string
		}{
			{"ML_KEM_512", "512"}, {"ML_KEM_768", "768"}, {"ML_KEM_1024", "1024"},
			{"MLKEM512", "512"}, {"MLKEM768", "768"}, {"MLKEM1024", "1024"},
		} {
			if strings.Contains(upper, marker.marker) {
				return "ML-KEM-" + marker.level
			}
		}
		if strings.Contains(upper, "GENERATEKEY1024") || strings.Contains(upper, "DECAPSULATIONKEY1024") || strings.Contains(upper, "ENCAPSULATIONKEY1024") {
			return "ML-KEM-1024"
		}
		if strings.Contains(upper, "GENERATEKEY768") || strings.Contains(upper, "DECAPSULATIONKEY768") || strings.Contains(upper, "ENCAPSULATIONKEY768") {
			return "ML-KEM-768"
		}
		return "ML-KEM"
	case strings.Contains(upper, "ML_DSA") || strings.Contains(upper, "MLDSA"):
		for _, marker := range []struct {
			marker string
			level  string
		}{
			{"ML_DSA_44", "44"}, {"ML_DSA_65", "65"}, {"ML_DSA_87", "87"},
			{"MLDSA44", "44"}, {"MLDSA65", "65"}, {"MLDSA87", "87"},
		} {
			if strings.Contains(upper, marker.marker) {
				return "ML-DSA-" + marker.level
			}
		}
		return "ML-DSA"
	case strings.Contains(upper, "SLH_DSA") || strings.Contains(upper, "SLHDSA"):
		return "SLH-DSA"
	case strings.Contains(upper, "CHACHA20POLY1305"):
		return "ChaCha20-Poly1305"
	case strings.Contains(upper, "BLAKE2"):
		return "BLAKE2b-512"
	case strings.Contains(upper, "SHA512"):
		return "SHA-512"
	case strings.Contains(upper, "SHA256"):
		return "SHA-256"
	case strings.Contains(upper, "X25519") || strings.Contains(upper, "CURVE25519"):
		return "X25519"
	case strings.Contains(upper, "P256") || strings.Contains(upper, "ECDSA"):
		return "ECDSA P-256"
	case strings.Contains(upper, "RSA"):
		return "RSA"
	case strings.Contains(upper, "SHA1"):
		return "SHA-1"
	case strings.Contains(upper, "SHA2"):
		if strings.Contains(upper, "256") {
			return "SHA-256"
		}
		if strings.Contains(upper, "512") {
			return "SHA-512"
		}
		return "SHA-2"
	case strings.Contains(upper, "HMAC"):
		return "HMAC"
	case strings.Contains(upper, "AES_GCM") || strings.Contains(upper, "/AES/GCM") || strings.Contains(upper, "AESGCM"):
		return "AES-GCM"
	case strings.Contains(upper, "AES"):
		return "AES"
	default:
		return ""
	}
}

func appendCandidate(candidates *[]CBOMCandidate, seen map[string]bool, candidate CBOMCandidate) {
	for i := range *candidates {
		if (*candidates)[i].Algorithm == candidate.Algorithm {
			if (*candidates)[i].API == "" {
				(*candidates)[i].API = candidate.API
			}
			for _, evidence := range candidate.Evidence {
				(*candidates)[i].Evidence = appendUniqueEvidence((*candidates)[i].Evidence, evidence)
			}
			return
		}
	}
	key := candidate.Algorithm
	*candidates = append(*candidates, candidate)
	seen[key] = true
}

func purposeFor(info KnowledgeRule, algorithm string) string {
	if info.Purpose != "" {
		return info.Purpose
	}
	upper := strings.ToUpper(algorithm)
	switch {
	case strings.Contains(upper, "SHA") || strings.Contains(upper, "BLAKE"):
		return "digest"
	case strings.Contains(upper, "HMAC"):
		return "message authentication"
	case strings.Contains(upper, "ECDSA") || strings.Contains(upper, "ED25519") || strings.Contains(upper, "RSA-PSS"):
		return "signature"
	case strings.Contains(upper, "ML-DSA") || strings.Contains(upper, "SLH-DSA"):
		return "signature"
	case strings.Contains(upper, "ML-KEM"):
		return "key encapsulation"
	case strings.Contains(upper, "X25519"):
		return "key agreement"
	case strings.Contains(upper, "RSA-OAEP"):
		return "key encapsulation"
	default:
		return "encryption"
	}
}

func algorithmFromImport(imported string, knowledge Knowledge) string {
	name := strings.TrimPrefix(imported, "_")
	for _, discovered := range knowledge.DiscoveredAlgorithms {
		for _, marker := range discovered.Imports {
			if strings.TrimPrefix(marker, "_") == name {
				return discovered.Algorithm
			}
		}
	}
	upper := strings.ToUpper(name)
	switch {
	case strings.Contains(upper, "CHACHA20_POLY1305"):
		return "ChaCha20-Poly1305"
	case strings.Contains(upper, "BLAKE2B"):
		return "BLAKE2b-512"
	case strings.Contains(upper, "SHA512") || strings.Contains(upper, "SHA-512"):
		return "SHA-512"
	case strings.Contains(upper, "AES_128_CBC"):
		return "AES-128-CBC"
	case strings.Contains(upper, "HMAC"):
		return "HMAC"
	default:
		return ""
	}
}

func algorithmsFromHint(hint string, knowledge Knowledge) []string {
	upper := strings.ToUpper(hint)
	var algorithms []string
	pqcPatterns := []string{`ML-KEM-[0-9]+`, `ML-DSA-[0-9]+`, `SLH-DSA-[A-Z0-9-]+`, `X25519MLKEM[0-9]+`, `X448MLKEM[0-9]+`}
	for _, pattern := range pqcPatterns {
		for _, match := range regexpFindAll(pattern, upper) {
			for _, discovered := range knowledge.DiscoveredAlgorithms {
				if strings.EqualFold(discovered.Algorithm, match) {
					algorithms = appendUnique(algorithms, discovered.Algorithm)
				}
			}
		}
	}
	if len(algorithms) > 0 {
		return algorithms
	}
	if algorithm := algorithmFromKnownHint(upper); algorithm != "" {
		return []string{algorithm}
	}
	return nil
}

func regexpFindAll(pattern, value string) []string {
	var result []string
	for _, token := range strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ':' || r == ' ' || r == '(' || r == ')'
	}) {
		if strings.Contains(token, "ML-KEM-") || strings.Contains(token, "ML-DSA-") || strings.Contains(token, "SLH-DSA-") || strings.Contains(token, "X25519MLKEM") || strings.Contains(token, "X448MLKEM") {
			result = append(result, strings.Trim(token, ".;"))
		}
	}
	return result
}

func algorithmFromKnownHint(upper string) string {
	switch {
	case strings.Contains(upper, "CHACHA20-POLY1305"):
		return "ChaCha20-Poly1305"
	case strings.Contains(upper, "HMAC-SHA512"):
		return "HMAC-SHA512"
	case strings.Contains(upper, "SHA-512"):
		return "SHA-512"
	case strings.Contains(upper, "BLAKE2B-512"):
		return "BLAKE2b-512"
	case strings.Contains(upper, "AES-128-CBC"):
		return "AES-128-CBC"
	case strings.Contains(upper, "X25519"):
		return "X25519"
	default:
		return ""
	}
}
