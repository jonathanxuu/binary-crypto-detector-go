# Binary Crypto Detector

使用 Go + LIEF + YARA 扫描 ELF、PE、Mach-O 二进制文件，输出密码算法依赖和 CBOM 风格资产清单。

工具按四层证据工作：

- 第 1 层，依赖：LIEF 读取 ELF、PE、Mach-O 的动态库依赖；
- 第 2 层，API/符号：读取导入函数；对静态链接的 Go、Rust、C++ 还读取加密相关普通符号；
- 第 3 层，算法特征：YARA 匹配算法字符串和字节特征，知识库匹配 API/符号；
- 第 4 层，语义推断：Go 合并证据，输出 `assets`、`candidates`、用途和置信度。

这意味着纯 Rust 静态二进制即使没有 OpenSSL/liboqs 动态依赖，也可以通过 `crypto_symbols` 和 `assets` 展示 RustCrypto 的算法代码。符号证据默认是 `medium`；只有动态导入或 YARA/API 多证据确认时才升级到 `high`。字符串线索仍然保留为 `candidates`，不会冒充已确认资产。

算法目录位于 `catalog/`。工具同时使用两类知识源：

- `catalog/*.json`：自己维护的高置信度 API 映射；
- `catalog/official-discovered.json`：从本机 OpenSSL 和 libsodium 官方接口自动发现的算法/API，只作为候选知识。

`knowledge.json` 和 `rules/crypto.yar` 都是生成文件，不需要直接修改。

## 1. 环境准备

需要安装 Go、Python 3、YARA；`jq` 可选，用于筛选 JSON。

macOS 可以执行：

```bash
brew install go python yara jq
```

进入工具目录：

```bash
cd ~/Downloads/github/binary-crypto-detector-go
```

创建 Python 虚拟环境并安装 LIEF：

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

## 2. 编译

```bash
go build -o binary-crypto-detector .
```

编译后主要文件如下：

```text
binary-crypto-detector   Go 主程序
lief-analyzer.py         LIEF 辅助分析器
knowledge.json           算法知识库
rules/crypto.yar         YARA 规则
```

程序会自动寻找当前目录或可执行文件目录旁边的 `.venv/bin/python`、`lief-analyzer.py`、`rules/crypto.yar` 和 `knowledge.json`。因此可以从任意目录调用。如果使用其他 Python 环境，可以显式指定：

```bash
LIEF_PYTHON=/path/to/python ./binary-crypto-detector --input ./sample
```

## 3. 扫描单个二进制文件

```bash
./binary-crypto-detector \
  --input ../03-crypto-tool-c/crypto-tool \
  --rules rules/crypto.yar \
  --knowledge knowledge.json
```

## 4. 批量扫描目录

使用 `--input-dir` 递归扫描目录中的疑似二进制文件。普通源码、README 和其他纯文本文件会自动跳过；每个结果占一行 JSON，适合直接保存为 JSONL：

```bash
./binary-crypto-detector \
  --input-dir ~/Documents/github/pqc-test-targets/10-multi-algorithm-binary-cases \
  --workers 4 \
  > results.jsonl
```

批量扫描的汇总信息会写到 stderr，不会污染 `results.jsonl`：

```text
scanned=5 errors=0 workers=4
```

查看批量结果：

```bash
jq -s 'map({file, assets, candidates, errors})' results.jsonl
```

如果有文件无法读取或知识库无法加载，程序仍会输出对应 JSON 行，并以退出码 `2` 结束。

## 5. 更新算法目录

先从本机已安装的官方库自动发现算法/API：

```bash
python3 scripts/update-catalog.py
python3 scripts/update-go-catalog.py
```

它会使用：

- OpenSSL 的 `openssl list`；
- libsodium 的公开头文件；

如需指定库位置：

```bash
LIBSODIUM_PREFIX="$(brew --prefix libsodium)" \
python3 scripts/update-catalog.py
```

然后生成检测器使用的知识库和 YARA 规则：

```bash
python3 scripts/generate-knowledge.py
```

脚本会自动重新生成：

```text
knowledge.json       Go 使用的算法映射
rules/crypto.yar     YARA 规则
```

如果自动发现的 API 需要提升为高置信度资产，再在 `catalog/openssl.json` 等文件中增加一个人工确认条目：

```json
{
  "id": "openssl.chacha20-poly1305",
  "rule": "OpenSSL_ChaCha20_Poly1305",
  "algorithm": "ChaCha20-Poly1305",
  "purpose": "AEAD encryption",
  "imports": ["EVP_chacha20_poly1305"],
  "evidence": ["EVP_chacha20_poly1305"],
  "yara_strings": ["EVP_chacha20_poly1305"]
}
```

不需要修改 Go 代码。生成后重新编译并扫描即可。

官方自动发现内容不会直接变成 `assets`，而是用于给 `candidates` 提供算法名称；只有确认过的映射才进入正式资产，避免把“库支持”误报成“程序使用”。

参数说明：

```text
--input       必填，要扫描的二进制文件
--rules       YARA 规则文件，默认 rules/crypto.yar
--knowledge   算法知识库，默认 knowledge.json
```

也可以从其他目录调用：

```bash
cd ~/Documents/github/pqc-test-targets/10-multi-algorithm-binary-cases

~/Downloads/github/binary-crypto-detector-go/binary-crypto-detector \
  --input target-chacha20-poly1305 \
  --rules ~/Downloads/github/binary-crypto-detector-go/rules/crypto.yar \
  --knowledge ~/Downloads/github/binary-crypto-detector-go/knowledge.json
```

## 6. 查看 CBOM 核心结果

完整输出包含文件哈希、导入函数和底层证据。如果只看 CBOM 核心字段，可以使用 `jq`：

```bash
./binary-crypto-detector \
  --input ../03-crypto-tool-c/crypto-tool \
  --rules rules/crypto.yar \
  --knowledge knowledge.json \
  | jq '{file, dependencies, assets, candidates}'
```

核心结构如下：

```json
{
  "file": "...",
  "dependencies": ["OpenSSL libcrypto"],
  "assets": [
    {
      "algorithm": "AES-256-GCM",
      "purpose": "AEAD encryption",
      "source": "binary",
      "api": "_EVP_aes_256_gcm",
      "evidence": [
        {
          "type": "lief_import",
          "value": "_EVP_aes_256_gcm",
          "strength": "high"
        }
      ],
      "confidence": "high"
    }
  ],
  "candidates": []
}
```

字段含义：

- `dependencies`：发现的密码库依赖，例如 `OpenSSL libcrypto`；
- `assets`：已经由 LIEF、YARA 和知识库确认的密码资产；
- `candidates`：发现了密码 API 或算法字符串，但知识库尚未正式映射的候选资产；
- `confidence`：当前证据强度，LIEF 导入函数通常高于单纯字符串匹配；
- `evidence`：支持判断的具体导入函数或匹配字符串。证据类型包括 `lief_import`、`yara_match` 和 `string_hint`；
- `errors`：导致本次扫描无法可靠完成的错误；出现时程序返回退出码 `2`；
- `warnings`：不影响继续输出的降级信息，例如 YARA 或 LIEF 不可用。

## 7. 批量扫描测试靶子

多算法靶子位于 `10-multi-algorithm-binary-cases`。先构建它们：

```bash
cd ~/Documents/github/pqc-test-targets/10-multi-algorithm-binary-cases
make OPENSSL_PREFIX="$(brew --prefix openssl@3)"
```

批量扫描：

```bash
for f in target-*; do
  if [[ "$f" != *.c ]]; then
    ~/Downloads/github/binary-crypto-detector-go/binary-crypto-detector \
      --input "$f" \
      --rules ~/Downloads/github/binary-crypto-detector-go/rules/crypto.yar \
      --knowledge ~/Downloads/github/binary-crypto-detector-go/knowledge.json \
      | jq '{file, dependencies, assets, candidates}'
  fi
done
```

这些靶子包括：

- ChaCha20-Poly1305；
- SHA-512、HMAC-SHA512；
- OpenSSL X25519；
- AES-128-CBC；
- BLAKE2b-512。

它们用于验证未知算法是否会进入 `candidates`，而不是直接被误报为已经确认的资产。

## 8. 扩展算法知识库

如果发现了新的导入函数，推荐把它加入 `catalog/*.json`，而不是直接编辑生成文件。完整流程是：

```text
_EVP_chacha20_poly1305
```

1. 在对应的 `catalog/*.json` 中加入映射；
2. 运行 `python3 scripts/generate-knowledge.py`；
3. 重新编译检测器；
4. 重新扫描样本。

生成条目示例：

```json
"OpenSSL_ChaCha20_Poly1305": {
  "library": "OpenSSL",
  "algorithm": "ChaCha20-Poly1305",
  "purpose": "AEAD encryption",
  "required_evidence": 1,
  "evidence": ["EVP_chacha20_poly1305"],
  "imports": ["EVP_chacha20_poly1305"]
}
```

重新生成后，该算法会从 `candidates` 变成正式的 `assets`。

## 9. 常见问题

### LIEF is not installed

在工具目录执行：

```bash
.venv/bin/pip install -r requirements.txt
go build -o binary-crypto-detector .
```

### YARA 执行失败

```bash
brew install yara
```

### `assets` 为空但 `imports` 有内容

这通常表示 LIEF 已经发现导入函数，但 `knowledge.json` 还没有对应映射：

```bash
... | jq '{imports, unrecognized_imports, algorithm_hints, candidates}'
```

### `candidates` 不是最终确认结果

候选资产只代表存在算法线索。确认前应结合导入函数、依赖库、YARA 证据和必要的人工复核，避免把普通字符串误认为实际使用的算法。
