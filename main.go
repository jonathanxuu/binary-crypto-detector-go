package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"
)

func main() {
	input := flag.String("input", "", "待扫描的二进制文件")
	inputDir := flag.String("input-dir", "", "递归扫描目录中的文件，并以 JSONL 输出")
	rules := flag.String("rules", "rules/crypto.yar", "YARA 规则文件")
	knowledgePath := flag.String("knowledge", "knowledge.json", "多证据知识库文件")
	workers := flag.Int("workers", runtime.NumCPU(), "批量扫描并发数")
	flag.Parse()
	if (*input == "" && *inputDir == "") || (*input != "" && *inputDir != "") {
		fmt.Println("用法：./binary-crypto-detector --input 二进制文件 | --input-dir 目录 [--rules rules/crypto.yar] [--knowledge knowledge.json] [--workers N]")
		os.Exit(1)
	}
	if *workers < 1 {
		fmt.Println("--workers 必须大于 0")
		os.Exit(1)
	}

	if *inputDir != "" {
		results, errors := scanDirectory(*inputDir, *rules, *knowledgePath, *workers)
		for _, result := range results {
			encoded, _ := json.Marshal(result)
			fmt.Println(string(encoded))
		}
		fmt.Fprintf(os.Stderr, "scanned=%d errors=%d workers=%d\n", len(results), errors, *workers)
		if errors > 0 {
			os.Exit(2)
		}
		return
	}

	result, err := scanBinary(*input, *rules, *knowledgePath)
	encoded, _ := json.MarshalIndent(result, "", "  ")
	fmt.Println(string(encoded))
	if err != nil {
		os.Exit(2)
	}
}
