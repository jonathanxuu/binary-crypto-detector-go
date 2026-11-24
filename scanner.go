package main

import (
	"crypto/sha256"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
)

func scanBinary(input, rulesPath, knowledgePath string) (Result, error) {
	data, err := os.ReadFile(input)
	if err != nil {
		result := Result{File: input, Errors: []string{err.Error()}}
		return result, err
	}
	sum := sha256.Sum256(data)
	result := Result{File: input, SHA256: hex.EncodeToString(sum[:]), Size: len(data)}
	result.Format, result.Architecture, result.Libraries = identifyBinary(input)
	if liefResult, err := runLIEF(input); err == nil {
		result.Imports = liefResult.Imports
		result.CryptoSymbols = liefResult.CryptoSymbols
		if len(liefResult.Libraries) > 0 {
			result.Libraries = liefResult.Libraries
		}
	} else {
		result.Warnings = append(result.Warnings, err.Error())
	}

	knowledge, err := loadKnowledge(resolveResourcePath(knowledgePath))
	if err != nil {
		result.Errors = append(result.Errors, err.Error())
		return result, err
	}
	rulesPath = resolveResourcePath(rulesPath)
	if output, err := exec.Command("yara", "-s", rulesPath, input).CombinedOutput(); err == nil {
		result.Findings = parseYARA(string(output), knowledge)
	} else {
		result.Warnings = append(result.Warnings, fmt.Sprintf("YARA 执行失败，请先执行 brew install yara：%s", strings.TrimSpace(string(output))))
	}

	result.Findings = mergeLIEFFindings(result.Findings, result.Imports, knowledge)
	result.Unrecognized = findUnrecognizedImports(result.Imports, knowledge)
	result.Hints = findAlgorithmHints(data)
	result.Dependencies = normalizeDependencies(result.Libraries)
	result.Assets, result.Candidates = buildCBOM(result.Findings, result.Unrecognized, result.Hints, result.CryptoSymbols, knowledge)
	return result, nil
}

func collectInputFiles(root string) ([]string, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("输入目录不是目录：%s", root)
	}
	var files []string
	err = filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path != root && strings.HasPrefix(info.Name(), ".") {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if info.IsDir() && strings.HasSuffix(info.Name(), ".dSYM") {
			return filepath.SkipDir
		}
		if info.Mode().IsRegular() && (filepath.Ext(info.Name()) == ".o" || filepath.Ext(info.Name()) == ".a") {
			return nil
		}
		if info.Mode().IsRegular() && isLikelyBinaryFile(path) {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	return files, nil
}

func isLikelyBinaryFile(path string) bool {
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()
	buffer := make([]byte, 4096)
	count, err := file.Read(buffer)
	if err != nil && count == 0 {
		return false
	}
	buffer = buffer[:count]
	if len(buffer) == 0 {
		return false
	}
	for _, b := range buffer {
		if b == 0 {
			return true
		}
	}
	for _, magic := range [][]byte{
		{0x7f, 'E', 'L', 'F'},
		{0xcf, 0xfa, 0xed, 0xfe},
		{0xfe, 0xed, 0xfa, 0xcf},
		{'M', 'Z'},
	} {
		if len(buffer) >= len(magic) {
			matched := true
			for i, value := range magic {
				if buffer[i] != value {
					matched = false
					break
				}
			}
			if matched {
				return true
			}
		}
	}
	return false
}

func scanDirectory(root, rulesPath, knowledgePath string, workers int) ([]Result, int) {
	files, err := collectInputFiles(root)
	if err != nil {
		return []Result{{File: root, Errors: []string{err.Error()}}}, 1
	}
	if workers > len(files) {
		workers = len(files)
	}
	if workers < 1 {
		workers = runtime.NumCPU()
	}

	results := make([]Result, len(files))
	jobs := make(chan int)
	var group sync.WaitGroup
	for i := 0; i < workers; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for index := range jobs {
				results[index], _ = scanBinary(files[index], rulesPath, knowledgePath)
			}
		}()
	}
	for index := range files {
		jobs <- index
	}
	close(jobs)
	group.Wait()

	errors := 0
	for _, result := range results {
		if len(result.Errors) > 0 {
			errors++
		}
	}
	return results, errors
}

func resolveResourcePath(path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	if _, err := os.Stat(path); err == nil {
		return path
	}
	if executable, err := os.Executable(); err == nil {
		candidate := filepath.Join(filepath.Dir(executable), path)
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return path
}

func runLIEF(path string) (LIEFResult, error) {
	python := os.Getenv("LIEF_PYTHON")
	if python == "" {
		python = "python3"
		venvPython := filepath.Join(".venv", "bin", "python")
		if _, err := os.Stat(venvPython); err == nil {
			python = venvPython
		} else if candidate := resolveResourcePath(venvPython); candidate != venvPython {
			python = candidate
		} else if executable, executableErr := os.Executable(); executableErr == nil {
			projectPython := filepath.Join(filepath.Dir(executable), ".venv", "bin", "python")
			if _, err := os.Stat(projectPython); err == nil {
				python = projectPython
			}
		}
	}
	analyzer := resolveResourcePath("lief-analyzer.py")
	output, err := exec.Command(python, analyzer, path).CombinedOutput()
	if err != nil {
		return LIEFResult{}, fmt.Errorf("LIEF 分析失败：%s", strings.TrimSpace(string(output)))
	}
	var result LIEFResult
	if err := json.Unmarshal(output, &result); err != nil {
		return LIEFResult{}, fmt.Errorf("LIEF 输出解析失败：%w", err)
	}
	return result, nil
}

func loadKnowledge(path string) (Knowledge, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Knowledge{}, fmt.Errorf("知识库加载失败：%w", err)
	}
	var knowledge Knowledge
	if err := json.Unmarshal(data, &knowledge); err != nil {
		return Knowledge{}, fmt.Errorf("知识库解析失败：%w", err)
	}
	return knowledge, nil
}

func identifyBinary(path string) (string, string, []string) {
	if file, err := elf.Open(path); err == nil {
		defer file.Close()
		libs, _ := file.ImportedLibraries()
		return "ELF", file.Machine.String(), libs
	}
	if file, err := pe.Open(path); err == nil {
		defer file.Close()
		return "PE", fmt.Sprint(file.Machine), nil
	}
	if file, err := macho.Open(path); err == nil {
		defer file.Close()
		var libs []string
		for _, load := range file.Loads {
			if dylib, ok := load.(*macho.Dylib); ok {
				libs = append(libs, dylib.Name)
			}
		}
		return "Mach-O", file.Cpu.String(), libs
	}
	return "", "", nil
}
