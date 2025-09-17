# GenCert - 证书生成

GenCert 是面向开发测试的纯 Go 证书工具，可一键生成根 CA、服务器/客户端证书并输出 PEM、PKCS12、JKS 等格式；支持多平台构建、交互式配置、日志追踪，让本地 HTTPS/TLS 搭建更高效安全。

## 特性

- 🔐 **全面输出**: 一次生成根CA、服务器/客户端证书及 PEM、PKCS12、JKS、TrustStore 全量制品
- 🌐 **多域名 & 通配符**: SAN 扩展、批量域名、`*.example.com` 通配符场景全覆盖
- 🧭 **零依赖部署**: 纯 Go 实现，跨 Windows、Linux、macOS 无须 OpenSSL
- 🛠️ **配置友好**: 支持 YAML 初始化、交互式向导、`--san`/`--config` 等多参数组合
- 📁 **结构化输出**: 所有生成文件统一落地到同级 `gencert-data/` 目录，便于备份与集成
- 📊 **可观测性**: 调试模式 + 文件日志定位问题更直观
- 🔧 **PKCS12 管理**: 支持密码修改、信息查看、安全验证，提供交互式与环境变量输入
- ☕ **Java 生态**: 自动生成 JKS 和 TrustStore，支持 keytool 验证，兼容 JDBC 连接
- 🔒 **证书链完整**: 自动构建服务器/客户端证书链，确保 SSL/TLS 双向认证完整性
- 🎯 **智能 CLI**: 现代化命令行界面，支持子命令、自动补全、参数校验
- 📦 **发布就绪**: 内置交叉编译、打包发布、版本管理和完整性校验
- 🛡️ **安全优先**: 健壮的错误处理、密码强度验证、文件权限控制

## 快速开始

### 安装

#### 从源码构建

##### Linux/macOS 系统

```bash
# 克隆仓库
git clone https://github.com/formzs/gencert.git
cd gencert

# 构建项目（要求 Go 1.22+；Makefile 会自动校验）
make build

# 或交叉编译所有平台
make build-all
```

##### Windows 系统

```cmd
# 克隆仓库
git clone https://github.com/formzs/gencert.git
cd gencert

# 构建项目 (使用批处理脚本)
REM 要求 Go 1.22+；脚本会自动校验
scripts\build-all.bat

# 或使用PowerShell脚本（脚本会自动校验 Go 1.22+）
powershell -ExecutionPolicy Bypass -File scripts\build-all.ps1

# 或直接构建当前平台
go build -o bin\gencert.exe cmd\gencert\main.go
```

#### 下载预编译版本

从 Releases 页面获取以下产物：

- 原始二进制：`gencert-windows-amd64.exe`、`gencert-linux-amd64`、`gencert-macos-{amd64|arm64}`
- 压缩包：
  - Windows：`gencert-windows-<arch>.zip`（压缩包内文件名为 `gencert.exe`）
  - Linux：`gencert-linux-<arch>.tar.gz`（压缩包内文件名为 `gencert`）
  - macOS：`gencert-macos-<arch>.tar.gz`（压缩包内文件名为 `gencert`）
- 校验文件：`sha256sums.txt`（二进制）与 `dist/sha256sums.txt`（压缩包）
- 可选签名：`dist/sha256sums.txt.asc`（GPG 署名）

下载与校验示例：

```bash
# Linux/macOS
curl -LO https://github.com/formzs/gencert/releases/download/vX.Y.Z/gencert-linux-amd64.tar.gz
curl -LO https://github.com/formzs/gencert/releases/download/vX.Y.Z/dist/sha256sums.txt
sha256sum -c sha256sums.txt | grep gencert-linux-amd64.tar.gz

# Windows (PowerShell)
Invoke-WebRequest -Uri "https://github.com/formzs/gencert/releases/download/vX.Y.Z/gencert-windows-amd64.zip" -OutFile gencert-windows-amd64.zip
Invoke-WebRequest -Uri "https://github.com/formzs/gencert/releases/download/vX.Y.Z/dist/sha256sums.txt" -OutFile sha256sums.txt
Get-FileHash gencert-windows-amd64.zip -Algorithm SHA256
```

### 使用方法

#### 基本用法

```bash
# 初始化配置文件
./gencert init

# 交互式初始化配置文件
./gencert init -i

# 指定配置文件路径初始化
./gencert init -c /path/to/config.yaml

# 生成单个域名的证书
./gencert example.com

# 批量生成多个域名的证书
./gencert example.com api.example.com admin.example.com

# 为证书添加额外的 SAN 域名
./gencert example.com --san api.example.com --san admin.example.com

# 生成通配符证书（注意为避免 shell 展开请加引号）
./gencert "*.example.com" --san api.rest.example.com

# 使用指定配置文件生成证书
./gencert -c configs/test.yaml generate test.example.com

# 启用调试模式
./gencert -d example.com

# 查看版本信息
./gencert -v
```

#### 命令行选项

- `-c, --config string`: 指定配置文件路径
- `-d, --debug`: 启用调试模式，显示详细日志
- `-v, --version`: 显示版本信息
- `-h, --help`: 显示帮助信息
- `--san value`: 为生成的证书追加 SAN 域名，可重复指定或使用逗号分隔

#### 子命令

- `init`: 初始化配置文件
  - `-i, --interactive`: 启用交互式配置
  - `-c, --config string`: 指定配置文件路径
- `generate`: 生成SSL证书
- `pkcs12`: 管理 PKCS12 证书包
  - `change-password`: 修改 PKCS12 密码（示例见下文）
  - `info`: 查看 PKCS12 信息（示例见下文）
- `help`: 显示帮助信息
- `completion`: 生成自动补全脚本

## 生成的文件

执行命令后，所有文件将统一写入程序目录同级的 `gencert-data/` 结构：

### 根证书
- `gencert-data/ca/rootCA.crt` - 根CA证书

### 服务器证书
- `gencert-data/certs/<safe-domain>.crt` - 服务器证书
- `gencert-data/certs/<safe-domain>.key` - 服务器私钥
- `gencert-data/certs/<safe-domain>-chain.pem` - 服务器证书链

### 客户端证书
- `gencert-data/certs/<safe-domain>-client.crt` - 客户端证书
- `gencert-data/certs/<safe-domain>-client.key` - 客户端私钥
- `gencert-data/certs/<safe-domain>-client-chain.pem` - 客户端证书链
- `gencert-data/certs/<safe-domain>-client.p12` - PKCS12 证书包（密码见配置 `pkcs12.default_password`，默认 HelloGenCert）
- `gencert-data/certs/<safe-domain>-client-windows.pfx` - Windows 兼容 PFX 文件
- `gencert-data/certs/<safe-domain>-client-info.txt` - 证书包说明

### Java 支持（可选）
- `gencert-data/certs/<safe-domain>-client.jks` - Java KeyStore（密码同 `pkcs12.default_password`）
- `gencert-data/certs/<safe-domain>-truststore.jks` - Java TrustStore（密码同 `pkcs12.default_password`）

> 提示：`<safe-domain>` 为经过文件名安全化处理的域名。例如 `*.example.com` 会生成 `gencert-data/certs/wildcard_.example.com.crt` 等文件，而证书内容仍保持 `*.example.com`。

### PKCS12 管理

```bash
# 修改 PKCS12 密码（若未提供 --old 则默认读取配置中的 pkcs12.default_password）
gencert pkcs12 change-password \
  --input gencert-data/certs/example.com-client.p12 \
  --old HelloGenCert \
  --new 'NewPass123!'

# 修改 PKCS12 密码并输出到新文件（避免覆盖原文件）
gencert pkcs12 change-password \
  --input gencert-data/certs/example.com-client.p12 \
  --new 'NewPass123!' \
  --output gencert-data/certs/example.com-client-new.p12

# 查看 PKCS12 信息（如未提供 --password，将尝试使用配置中的默认密码）
gencert pkcs12 info \
  --input gencert-data/certs/example.com-client.p12 \
  --password 'NewPass123!'
```

支持通过环境变量与交互式输入提供密码（推荐，避免命令历史明文）：

- `GENCERT_OLD_PASSWORD`: change-password 旧密码（缺省则使用配置默认密码）
- `GENCERT_NEW_PASSWORD`: change-password 新密码（缺省则进入交互式输入，禁回显）
- `GENCERT_P12_PASSWORD`: info 命令密码（缺省则进入交互式输入，禁回显；再缺省回退到配置默认密码）

CI/非交互环境可添加 `--no-prompt` 禁用交互输入，仅从参数或环境变量读取。

安全提示：
- 尽量避免将密码置于命令参数中（会出现在 history/进程列表），优先使用交互式或环境变量。
- 生成新文件时可用 `--output` 避免覆盖原文件，按需自行清理旧文件。

## 配置文件

GenCert支持灵活的配置文件管理，可以通过 `init` 命令创建配置文件，也可以在生成证书时指定配置文件路径。

### 配置文件初始化

```bash
# 创建默认配置文件
./gencert init

# 交互式创建配置文件
./gencert init -i

# 指定路径创建配置文件
./gencert init -c /path/to/custom-config.yaml
```

### 配置示例

```yaml
# GenCert 配置文件
# 这是 GenCert 的默认配置文件，您可以根据需要修改

# 调试模式
debug: false

# 目录配置
root_ca_dir: ../gencert-data/ca
cert_dir: ../gencert-data/certs
log_dir: ../gencert-data/logs

# 证书主题信息
country: CN
state: Beijing
locality: ChaoYang
organization: CA
org_unit: Development
common_name: Development CA

# 证书参数
default_bits: 2048
default_days: 3650

# PKCS12配置
pkcs12:
  default_password: "HelloGenCert"
  friendly_name: "GenCert Client Certificate"
```

### 配置说明

- `debug`: 是否启用调试模式
- `country`: 国家代码（2字母）
- `state`: 省份或州
- `locality`: 城市
- `organization`: 组织名称
- `org_unit`: 组织单位
- `common_name`: 默认域名
- `default_bits`: 密钥长度（2048或4096）
- `default_days`: 证书有效期（天）
- `root_ca_dir`: 根CA证书目录
- `cert_dir`: 证书文件目录
- `log_dir`: 日志文件目录
- `pkcs12.default_password`: PKCS12默认密码
- `pkcs12.friendly_name`: PKCS12友好名称

### 使用自定义配置文件

```bash
# 使用自定义配置文件生成证书
./gencert -c /path/to/config.yaml generate example.com

# 或在命令中指定配置文件
./gencert -c configs/production.yaml generate api.example.com
```

## 项目结构

```
gencert/
├── cmd/gencert/           # 主程序入口
├── internal/             # 内部包
│   ├── config/          # 配置管理
│   ├── crypto/          # 加密和证书操作
│   ├── logger/          # 日志系统
│   ├── utils/           # 工具函数
│   └── version/         # 版本信息
├── pkg/                 # 公共包
│   └── cli/             # 命令行接口
├── configs/             # 配置文件
├── scripts/             # 构建脚本
├── bin/                 # 编译输出
├── Makefile            # 构建配置
└── README.md            # 说明文档
```

## 开发

### 环境要求

- Go 1.22+
- Git

### 构建和测试

#### Linux/macOS 系统

```bash
# 下载依赖
make deps

# 构建项目
make build

# 运行测试
make test

# 生成测试覆盖率报告
make test-coverage

# 代码检查
make check

# 运行示例
make example-simple
```

#### Windows 系统

```cmd
# 下载依赖
go mod download
go mod tidy

# 构建项目
scripts\build-all.bat

# 运行测试
go test -v ./...

# 生成测试覆盖率报告
go test -v -coverprofile=coverage.out ./...
go tool cover -html=coverage.out -o coverage.html

# 代码格式化
go fmt ./...

# 静态检查
go vet ./...

# 运行示例
.\bin\gencert-windows-amd64.exe example.com
```

### 开发模式

```bash
# 开发模式运行（带调试信息）
make run-dev ARGS="example.com"

# 格式化代码
make fmt

# 静态检查
make vet
```

## 部署

### 交叉编译

```bash
# 构建所有平台
make build-all

# 构建特定平台
make build-linux    # Linux
make build-windows  # Windows
make build-darwin   # macOS (同时生成 amd64 与 arm64)
```

运行 `build-all` 脚本或上述 Make 目标后，`bin/` 目录会包含：

- `gencert-windows-amd64.exe`
- `gencert-linux-amd64`
- `gencert-macos-amd64`
- `gencert-macos-arm64`

Windows/PowerShell 脚本也会额外生成同名产物，方便直接发布。


## 使用场景

### HTTPS服务器配置

```nginx
server {
    listen 443 ssl http2;
    server_name example.com;

    # 服务器证书
    ssl_certificate ./certs/example.com-chain.pem;
    ssl_certificate_key ./certs/example.com.key;

    # 客户端证书验证（双向认证）
    ssl_client_certificate ./ca/rootCA.crt;
    ssl_verify_client on;

    # SSL配置
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';
    ssl_prefer_server_ciphers on;
}
```

### PostgreSQL JDBC连接

```java
// 使用PEM格式
String url = "jdbc:postgresql://example.com:5432/dbname?" +
    "ssl=true&sslmode=verify-full&" +
    "sslrootcert=./ca/rootCA.crt&" +
    "sslcert=./certs/example.com-client.crt&" +
    "sslkey=./certs/example.com-client.key";

// 使用PKCS12格式（推荐）
String url = "jdbc:postgresql://example.com:5432/dbname?" +
    "ssl=true&sslmode=verify-full&" +
    "sslrootcert=./ca/rootCA.crt&" +
    "sslcert=./certs/example.com-client.p12&" +
    "sslpassword=<配置中的 pkcs12.default_password>";
```

## 故障排除

### 常见问题

1. **Windows下make命令不存在**
   ```cmd
   # 使用Windows构建脚本
   scripts\build-all.bat

   # 或使用PowerShell脚本
   powershell -ExecutionPolicy Bypass -File scripts\build-all.ps1

   # 或直接使用go命令构建
   go build -o bin\gencert.exe cmd\gencert\main.go
   ```

2. **权限错误**
   ```bash
   # Linux/macOS
   chmod +x gencert

   # Windows
   # 以管理员身份运行命令提示符或PowerShell
   ```

3. **证书已存在**
   ```bash
   # Linux/macOS
   rm -rf ca/ certs/

   # Windows
   rmdir /s /q ca
   rmdir /s /q certs
   ```

4. **配置文件错误**
   ```bash
   # Linux/macOS
   rm configs/cert.yaml

   # Windows
   del configs\cert.yaml
   ```

5. **调试模式**
   ```bash
   # Linux/macOS
   ./gencert -d example.com

   # Windows
   .\bin\gencert.exe -d example.com
   ```

### 日志文件

日志文件位于 `logs/` 目录：
- `gencert_YYYYMMDD_HHMMSS.log` - 主日志文件
- `error.log` - 错误日志

## 贡献

欢迎提交Issue和Pull Request！

### 开发流程

1. Fork项目
2. 创建功能分支
3. 提交更改
4. 创建Pull Request

### 代码规范

- 遵循Go代码规范
- 添加必要的注释
- 编写单元测试
- 更新文档




## 更新日志

### v1.2.0 (2025-09-17)
- ✨ 新增 PKCS12 子命令：
  - `gencert pkcs12 change-password` 支持交互式输入（禁回显）、环境变量回退（GENCERT_OLD_PASSWORD/GENCERT_NEW_PASSWORD）、`--output` 输出到新文件避免覆盖
  - `gencert pkcs12 info` 支持交互式输入与环境变量回退（GENCERT_P12_PASSWORD），展示友好信息（证书链/算法/序列号等）
- 🔧 最低 Go 版本要求提升至 1.22，并在 Makefile 与构建脚本中自动校验
- 🔧 构建与发布：
  - CI：新增多平台（Linux/Windows/macOS）× 多 Go 版本（1.22/1.23/1.24）矩阵
  - Release：新增打包 zip（Windows）与 tar.gz（Linux/macOS），生成 dist/sha256sums.txt，支持可选 GPG 签名（dist/sha256sums.txt.asc）
  - 脚本：Windows 跨平台构建改为 PowerShell 主驱动（build-all.ps1），`build-all.bat` 为 PS 代理；`build.bat` 作为无 PS 的单平台兜底
- 🐞 修复 Windows 在 UTF-8 代码页下 cmd 解析导致的“not recognized”噪音问题（通过 PowerShell 构建与薄代理规避）
- 📝 文档：新增 PKCS12 管理示例、下载与校验/签名说明

### v1.1.0 (2025-09-16)
- 🔧 新增配置文件初始化功能 (`gencert init`)
- 🎯 支持交互式配置文件创建 (`gencert init -i`)
- 📁 支持指定配置文件路径 (`gencert init -c /path/to/config.yaml`)
- 🚀 支持使用指定配置文件生成证书 (`gencert -c config.yaml generate domain.com`)
- 📋 增强的CLI命令结构，支持子命令和参数
- 📝 完善的配置文件文档和示例
- 🔍 改进的错误处理和用户提示

### v1.0.0 (2025-09-16)
- 🎉 首个稳定版本发布
- 🔧 完整的证书生成功能（根CA、服务器证书、客户端证书）
- 🌐 完善的多域名SAN扩展支持
- 📦 真正的PKCS12格式支持（包含完整的证书链）
- 🧪 全面的单元测试和集成测试覆盖
- 🛡️ 健壮的错误处理机制
- 📝 详细的配置管理和日志系统
- 🔍 OpenSSL兼容性验证通过
- 🚀 跨平台支持（Windows、Linux、macOS）

## 支持

如果您遇到问题或有建议，请：
- 提交 [Issue](https://github.com/formzs/gencert/issues)
- 仔细查看README.md
---

**GenCert** - 让证书生成变得简单！

## 许可证

MIT License