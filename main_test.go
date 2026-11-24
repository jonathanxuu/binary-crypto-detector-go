package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMergeLIEFFindingsRequiresAllEvidence(t *testing.T) {
	knowledge := Knowledge{Rules: map[string]KnowledgeRule{
		"hmac": {
			Library:          "OpenSSL",
			Algorithm:        "HMAC-SHA512",
			RequiredEvidence: 2,
			Imports:          []string{"HMAC", "EVP_sha512"},
			Status:           "curated",
		},
	}}

	if got := mergeLIEFFindings(nil, []string{"_HMAC"}, knowledge); len(got) != 0 {
		t.Fatalf("single evidence should not confirm HMAC-SHA512: %#v", got)
	}
	findings := mergeLIEFFindings(nil, []string{"_HMAC", "_EVP_sha512"}, knowledge)
	if len(findings) != 1 || len(findings[0].Evidence) != 2 {
		t.Fatalf("expected two-evidence confirmation: %#v", findings)
	}
}

func TestNormalizeDependencies(t *testing.T) {
	got := normalizeDependencies([]string{
		"/opt/lib/libcrypto.4.dylib",
		"/usr/lib/libSystem.B.dylib",
		"/opt/lib/libcrypto.4.dylib",
	})
	if len(got) != 1 || got[0] != "OpenSSL libcrypto" {
		t.Fatalf("unexpected dependencies: %#v", got)
	}
}

func TestBuildCBOMRecordsMappingSource(t *testing.T) {
	knowledge := Knowledge{Rules: map[string]KnowledgeRule{
		"auto": {
			Library:          "OpenSSL",
			Algorithm:        "AES-128-CBC",
			Purpose:          "encryption",
			RequiredEvidence: 1,
			Imports:          []string{"EVP_aes_128_cbc"},
			Status:           "official-discovered",
		},
	}}
	findings := mergeLIEFFindings(nil, []string{"_EVP_aes_128_cbc"}, knowledge)
	assets, _ := buildCBOM(findings, nil, nil, nil, knowledge)
	if len(assets) != 1 || assets[0].Mapping != "official-discovered" {
		t.Fatalf("mapping source missing: %#v", assets)
	}
}

func TestResolveResourcePathKeepsExistingPath(t *testing.T) {
	dir := t.TempDir()
	resource := filepath.Join(dir, "resource.json")
	if err := os.WriteFile(resource, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if got := resolveResourcePath(resource); got != resource {
		t.Fatalf("absolute resource path changed: %q", got)
	}
}

func TestScanBinaryReturnsErrorForMissingInput(t *testing.T) {
	_, err := scanBinary(filepath.Join(t.TempDir(), "missing"), "rules/crypto.yar", "knowledge.json")
	if err == nil {
		t.Fatal("missing input should return an error")
	}
}

func TestCollectInputFilesReturnsSortedRegularFiles(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "nested"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"z.bin", filepath.Join("nested", "a.bin")} {
		if err := os.WriteFile(filepath.Join(root, name), []byte{'M', 'Z', 0, 1}, 0600); err != nil {
			t.Fatal(err)
		}
	}
	files, err := collectInputFiles(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 || files[0] > files[1] {
		t.Fatalf("files should be sorted: %#v", files)
	}
	textFile := filepath.Join(root, "README.md")
	if err := os.WriteFile(textFile, []byte("plain text"), 0600); err != nil {
		t.Fatal(err)
	}
	if isLikelyBinaryFile(textFile) {
		t.Fatal("plain text should not be treated as binary")
	}
}
