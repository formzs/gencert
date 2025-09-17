# GenCert Makefile

.PHONY: build build-all build-linux build-windows build-darwin clean test test-unit test-integration deps install run help check-go

# 默认目标
.DEFAULT_GOAL := help

# 版本信息
VERSION := $(shell go run ./scripts/version)
BUILD_TIME := $(shell date -u '+%Y-%m-%d_%H:%M:%S')
COMMIT_HASH := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# 目录
OUTPUT_DIR := bin
CONFIG_DIR := configs
EXAMPLES_DIR := examples
SCRIPTS_DIR := scripts

# 构建变量
LDFLAGS := -X 'github.com/formzs/gencert/internal/version.Version=$(VERSION)' -X 'github.com/formzs/gencert/internal/version.BuildTime=$(BUILD_TIME)' -X 'github.com/formzs/gencert/internal/version.CommitHash=$(COMMIT_HASH)'

##@ 帮助信息
help: ## 显示帮助信息
	@echo "GenCert 构建工具"
	@echo "版本: $(VERSION)"
	@echo ""
	@awk 'BEGIN {FS = ":.*##"; printf "\n用法:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ 构建目标
check-go:
	@bash -c 'set -e; if ! command -v go >/dev/null 2>&1; then echo "未检测到 Go，请先安装 Go 1.22+"; exit 1; fi; v=$$(go version | awk '{print $$3}' | sed "s/go//"); maj=$${v%%.*}; rest=$${v#*.}; min=$${rest%%.*}; if [ -z "$$maj" ] || [ -z "$$min" ]; then echo "无法解析 Go 版本: $$v"; exit 1; fi; if [ $$maj -lt 1 ] || { [ $$maj -eq 1 ] && [ $$min -lt 22 ]; }; then echo "需要 Go >= 1.22，当前: $$v"; exit 1; fi; echo "Go 版本满足要求: $$v"'

build: check-go ## 构建当前平台的二进制文件
	@echo "构建当前平台..."
	@mkdir -p $(OUTPUT_DIR)
	go build -ldflags="$(LDFLAGS)" -o $(OUTPUT_DIR)/gencert ./cmd/gencert

build-all: check-go ## 构建所有支持的平台
	@echo "构建所有平台..."
	@chmod +x $(SCRIPTS_DIR)/build.sh
	@$(SCRIPTS_DIR)/build.sh

build-linux: check-go ## 构建 Linux 版本
	@echo "构建 Linux 版本..."
	@mkdir -p $(OUTPUT_DIR)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o $(OUTPUT_DIR)/gencert-linux-amd64 ./cmd/gencert

build-windows: check-go ## 构建 Windows 版本
	@echo "构建 Windows 版本..."
	@mkdir -p $(OUTPUT_DIR)
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o $(OUTPUT_DIR)/gencert-windows-amd64.exe ./cmd/gencert

build-darwin: check-go ## 构建 macOS 版本
	@echo "构建 macOS 版本..."
	@mkdir -p $(OUTPUT_DIR)
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o $(OUTPUT_DIR)/gencert-macos-amd64 ./cmd/gencert
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o $(OUTPUT_DIR)/gencert-macos-arm64 ./cmd/gencert

##@ 测试目标
test: ## 运行所有测试
	@echo "运行所有测试..."
	go test -v ./...

test-unit: ## 运行单元测试
	@echo "运行单元测试..."
	go test -v -short ./...

test-integration: ## 运行集成测试
	@echo "运行集成测试..."
	go test -v -run Integration ./...

test-coverage: ## 生成测试覆盖率报告
	@echo "生成测试覆盖率报告..."
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "覆盖率报告已生成: coverage.html"

##@ 依赖管理
deps: ## 下载依赖
	@echo "下载依赖..."
	go mod download
	go mod tidy

deps-update: ## 更新依赖
	@echo "更新依赖..."
	go get -u ./...
	go mod tidy

deps-clean: ## 清理依赖缓存
	@echo "清理依赖缓存..."
	go clean -modcache
	go mod tidy

##@ 安装目标
install: ## 安装到本地
	@echo "安装到本地..."
	go install -ldflags="$(LDFLAGS)" ./cmd/gencert

install-local: ## 安装到本地bin目录
	@echo "安装到本地bin目录..."
	@mkdir -p $(HOME)/bin
	cp $(OUTPUT_DIR)/gencert $(HOME)/bin/
	@echo "已安装到: $(HOME)/bin/gencert"
	@echo "请确保 $(HOME)/bin 在您的PATH中"

##@ 运行目标
run: ## 运行程序
	@echo "运行程序..."
	go run ./cmd/gencert $(ARGS)

run-dev: ## 开发模式运行
	@echo "开发模式运行..."
	go run -ldflags="$(LDFLAGS)" ./cmd/gencert -d $(ARGS)

##@ 清理目标
clean: ## 清理构建文件
	@echo "清理构建文件..."
	rm -rf $(OUTPUT_DIR)
	rm -f coverage.out coverage.html

clean-all: clean ## 清理所有生成文件
	@echo "清理所有生成文件..."
	rm -rf $(OUTPUT_DIR)
	rm -f coverage.out coverage.html
	go clean -cache -testcache -modcache


##@ 开发目标
fmt: ## 格式化代码
	@echo "格式化代码..."
	go fmt ./...

lint: ## 运行代码检查
	@echo "运行代码检查..."
	golangci-lint run

vet: ## 运行静态检查
	@echo "运行静态检查..."
	go vet ./...

check: fmt lint vet ## 运行所有检查

##@ 文档目标
docs: ## 生成文档
	@echo "生成文档..."
	godoc -http=:6060

##@ 版本目标
version: ## 显示版本信息
	@echo "版本: $(VERSION)"
	@echo "构建时间: $(BUILD_TIME)"
	@echo "提交哈希: $(COMMIT_HASH)"

release: ## 创建发布版本
	@echo "创建发布版本 v$(VERSION)..."
	git tag v$(VERSION)
	git push origin v$(VERSION)
	@echo "发布版本 v$(VERSION) 已创建"

##@ 示例目标
example-simple: ## 生成简单示例证书
	@echo "生成简单示例证书..."
	./$(OUTPUT_DIR)/gencert example.com

example-multi: ## 生成多域名示例证书
	@echo "生成多域名示例证书..."
	./$(OUTPUT_DIR)/gencert example.com api.example.com admin.example.com
