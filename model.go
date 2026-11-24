package main

type Finding struct {
	Rule      string     `json:"rule"`
	Library   string     `json:"library,omitempty"`
	Algorithm string     `json:"algorithm,omitempty"`
	Evidence  []Evidence `json:"evidence,omitempty"`
}

type Evidence struct {
	Type     string `json:"type"`
	Value    string `json:"value"`
	Strength string `json:"strength"`
}

type CBOMAsset struct {
	Algorithm  string     `json:"algorithm"`
	Purpose    string     `json:"purpose,omitempty"`
	Source     string     `json:"source"`
	API        string     `json:"api,omitempty"`
	Evidence   []Evidence `json:"evidence,omitempty"`
	Confidence string     `json:"confidence,omitempty"`
	Mapping    string     `json:"mapping,omitempty"`
}

type CBOMCandidate struct {
	Algorithm  string     `json:"algorithm,omitempty"`
	API        string     `json:"api,omitempty"`
	Evidence   []Evidence `json:"evidence"`
	Confidence string     `json:"confidence"`
}

type LIEFResult struct {
	Format        string   `json:"format"`
	Libraries     []string `json:"libraries"`
	Imports       []string `json:"imports"`
	CryptoSymbols []string `json:"crypto_symbols"`
}

type Result struct {
	File          string          `json:"file"`
	SHA256        string          `json:"sha256"`
	Size          int             `json:"size"`
	Dependencies  []string        `json:"dependencies,omitempty"`
	Assets        []CBOMAsset     `json:"assets,omitempty"`
	Candidates    []CBOMCandidate `json:"candidates,omitempty"`
	Format        string          `json:"format,omitempty"`
	Architecture  string          `json:"architecture,omitempty"`
	Libraries     []string        `json:"libraries,omitempty"`
	Imports       []string        `json:"imports,omitempty"`
	CryptoSymbols []string        `json:"crypto_symbols,omitempty"`
	Unrecognized  []string        `json:"unrecognized_imports,omitempty"`
	Hints         []string        `json:"algorithm_hints,omitempty"`
	Findings      []Finding       `json:"findings,omitempty"`
	Warnings      []string        `json:"warnings,omitempty"`
	Errors        []string        `json:"errors,omitempty"`
}

type Knowledge struct {
	Rules                map[string]KnowledgeRule `json:"rules"`
	DiscoveredAlgorithms []DiscoveredAlgorithm    `json:"discovered_algorithms"`
}

type DiscoveredAlgorithm struct {
	Algorithm string   `json:"algorithm"`
	Purpose   string   `json:"purpose"`
	Imports   []string `json:"imports"`
	Aliases   []string `json:"aliases,omitempty"`
	Library   string   `json:"library,omitempty"`
	Source    string   `json:"source,omitempty"`
	Status    string   `json:"status,omitempty"`
}

type KnowledgeRule struct {
	Library          string   `json:"library"`
	Algorithm        string   `json:"algorithm"`
	Purpose          string   `json:"purpose"`
	RequiredEvidence int      `json:"required_evidence"`
	Evidence         []string `json:"evidence"`
	Imports          []string `json:"imports"`
	Symbols          []string `json:"symbols,omitempty"`
	Status           string   `json:"status,omitempty"`
	Source           string   `json:"source,omitempty"`
}
