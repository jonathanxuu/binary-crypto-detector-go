# Algorithm catalog

这里是算法知识库的源文件。不要直接手工编辑生成后的 `knowledge.json` 或 `rules/crypto.yar`。

知识来源有两条：

- `*.json`：项目自己维护的高置信度映射；
- `official-discovered.json`：由 OpenSSL 命令和 libsodium 公开头文件自动发现的候选条目。
- `go-official.json`：由本机 Go 标准库和已安装的 `golang.org/x/crypto` 模块自动发现的包/符号映射。

官方目录会记录算法别名，例如 `MLKEM768` 会归一化为 `ML-KEM-768`，避免统计重复。

新增或修改算法后，在工具目录执行：

```bash
python3 scripts/update-catalog.py
python3 scripts/update-go-catalog.py
python3 scripts/generate-knowledge.py
```

脚本会重新生成：

- `knowledge.json`：Go 检测器使用的算法映射；
- `rules/crypto.yar`：YARA 字符串规则。
