#!/bin/bash

# GenCert 构建脚本
# 支持多平台交叉编译

set -e

# 获取脚本所在目录
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Go 版本检查（要求 >= 1.22）
if ! command -v go >/dev/null 2>&1; then
  echo "未检测到 Go，请先安装 Go 1.22+" >&2
  exit 1
fi
GV=$(go version | awk '{print $3}' | sed 's/go//')
MAJ=${GV%%.*}
TMP=${GV#*.}
MIN=${TMP%%.*}
if [ -z "$MAJ" ] || [ -z "$MIN" ]; then
  echo "无法解析 Go 版本: $GV" >&2
  exit 1
fi
if [ "$MAJ" -lt 1 ] || { [ "$MAJ" -eq 1 ] && [ "$MIN" -lt 22 ]; }; then
  echo "需要 Go >= 1.22，当前: $GV" >&2
  exit 1
fi
echo "Go 版本满足要求: $GV"

# 版本信息
VERSION=$(cd "$PROJECT_ROOT" && go run ./scripts/version)
BUILD_TIME=$(date -u '+%Y-%m-%d_%H:%M:%S')
COMMIT_HASH=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# 构建配置
BUILD_OS=("windows" "linux" "darwin")
BUILD_ARCH=("amd64" "arm64" "386")

# 输出目录
OUTPUT_DIR="$PROJECT_ROOT/bin"
mkdir -p "$OUTPUT_DIR"

# 构建函数
build_binary() {
    local os=$1
    local arch=$2
    local label=$os
    local ext=""
    if [ "$os" = "darwin" ]; then
        label="macos"
    fi
    if [ "$os" = "windows" ]; then
        ext=".exe"
    fi
    local output_path="$OUTPUT_DIR/gencert-${label}-${arch}${ext}"

    echo "构建 $os/$arch..."

    # 设置构建变量
    export GOOS="$os"
    export GOARCH="$arch"
    export CGO_ENABLED=0

    # 构建命令（在项目根目录执行，避免相对路径问题）
    (cd "$PROJECT_ROOT" && go build \
        -ldflags="-X 'github.com/formzs/gencert/internal/version.Version=$VERSION' -X 'github.com/formzs/gencert/internal/version.BuildTime=$BUILD_TIME' -X 'github.com/formzs/gencert/internal/version.CommitHash=$COMMIT_HASH'" \
        -o "$output_path" \
        ./cmd/gencert)

    echo "✓ 构建完成: $output_path"
}

# 主构建过程
echo "GenCert 构建脚本"
echo "版本: $VERSION"
echo "构建时间: $BUILD_TIME"
echo "提交哈希: $COMMIT_HASH"
echo "====================="

# 清理旧的构建文件
rm -f "$OUTPUT_DIR/gencert-"*

# 构建所有平台组合
for os in "${BUILD_OS[@]}"; do
    for arch in "${BUILD_ARCH[@]}"; do
        # 跳过不支持的组合
        if [ "$os" = "windows" ] && [ "$arch" = "arm64" ]; then
            continue
        fi
        if [ "$os" = "darwin" ] && [ "$arch" = "386" ]; then
            continue
        fi
        build_binary "$os" "$arch"
    done
done

echo "====================="
echo "构建完成！"
echo "输出目录: $OUTPUT_DIR"
echo ""

# 显示构建结果
ls -la "$OUTPUT_DIR/gencert-"* 2>/dev/null | head -10 || true

# 创建校验和文件（兼容 sha256sum/shasum）
echo "创建校验和文件..."
cd "$OUTPUT_DIR"
if command -v sha256sum >/dev/null 2>&1; then
  for file in gencert-*; do
    [ -f "$file" ] || continue
    sha256sum "$file" >> sha256sums.txt
  done
elif command -v shasum >/dev/null 2>&1; then
  for file in gencert-*; do
    [ -f "$file" ] || continue
    shasum -a 256 "$file" | awk '{print $1, " ", $2}' >> sha256sums.txt
  done
else
  echo "未找到 sha256sum/shasum，跳过校验和生成" >&2
fi
echo "校验和文件: sha256sums.txt"
