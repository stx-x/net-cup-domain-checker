# .li 域名可用性扫描工具

这是一个灵活的 .li 域名可用性扫描工具，可以根据用户定义的条件组合扫描可注册的 .li 域名。

## 功能特点

- **灵活的扫描配置**：支持指定域名长度、字符集和生成方法
- **多种生成方法**：
  - 所有组合：生成指定长度和字符集的所有可能组合
  - 字典匹配：从字典文件中查找符合长度和字符集要求的单词
  - 连续重复模式：生成包含连续重复字符的域名
  - 拼音匹配：从拼音字典中查找符合条件的拼音
- **实时结果输出**：扫描过程中实时将可用域名写入文件，无需等待扫描完成
- **错误处理**：健壮的网络错误处理和自动重试机制
- **详细模式**：可选择输出每个查询域名的详细状态

## 安装

只需克隆此仓库：

```bash
git clone https://github.com/stx-x/net-cup-domain-checker
cd net-cup-domain-checker
```
## 查看帮助 这个比下面的准

```bash
python main.py -h
```

## 使用方法

```bash
python main.py -l 长度 -c 字符集 -m 方法1 [方法2 ...] -o results.txt
```

### 必需参数

- `-l, --length`：要扫描的域名主体长度（不含 .li 后缀）
- `-m, --methods`：域名生成方法，可选择多个：
  - `all`：生成所有可能的组合
  - `dict`：从字典文件中查找
  - `repeats`：生成包含连续重复字符的域名
  - `pinyin`：从拼音字典文件中查找

### 可选参数

- `-c, --chars`：字符集类型 (默认: `alnum`)
  - `letters`：仅小写字母 (a-z)
  - `digits`：仅数字 (0-9)
  - `alnum`：字母和数字
  - `letters-hyphen`：字母和连字符
  - `digits-hyphen`：数字和连字符
  - `alnum-hyphen`：字母、数字和连字符
- `-o, --output`：可选：将找到的可用域名写入指定的文件路径。 (default: None)
- `--live-log`: 指定实时日志文件，可用域名会被立即写入此文件 (可在扫描过程中查看) (default: None)
- `--min-repeats`：指定最少连续重复字符数量 (默认: 2)
- `--dict-file`：字典文件的路径 (默认: /usr/share/dict/words)
- `--pinyin-dict-file`：拼音字典文件的路径
- `--delay`：每次查询之间的延迟秒数 (默认: 1.0)
- `--max-retries`：连接失败时的最大重试次数 (默认: 2)
- `-v, --verbose`：显示每个查询域名的详细状态

## 示例

### 扫描所有3位数字域名
```bash
python main.py -l 3 -c digits -m all --live-log log.txt
```

### 扫描包含至少3个连续相同字母的5位域名
```bash
python main.py -l 5 -c letters -m repeats --min-repeats 3 --live-log log.txt
```

### 从字典和拼音两个来源扫描4位域名
```bash
python main.py -l 4 -c alnum -m dict pinyin --pinyin-dict-file pinyin.txt --live-log log.txt
```

### 使用详细模式并指定输出文件
```bash
python main.py -l 3 -c alnum-hyphen -m all -v -o results.txt
```

## 注意事项

1. 使用 `all` 方法生成较长域名时会产生大量组合，请谨慎设置参数
2. 设置合理的查询延迟（`--delay`）以避免触发频率限制
3. 结果会实时写入输出文件，可在扫描过程中查看
4. 对于拼音方法，需要提供拼音字典文件（每行一个拼音）

## 错误代码说明

- 代码 1: 域名可以注册
- 代码 0: 域名已被注册
- 代码 -1: 无效查询
- 代码 -95: 访问受限 (稍后重试)
- 代码 -99: 服务器临时错误 (稍后重试)

## 许可

MIT 许可证
