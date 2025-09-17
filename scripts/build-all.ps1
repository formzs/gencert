# GenCert PowerShell 构建脚本
# 支持多平台交叉编译

# 获取脚本目录并进入项目根目录
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$projectRoot = Resolve-Path (Join-Path $scriptDir "..")
Push-Location $projectRoot

try {
    Write-Host "GenCert PowerShell 构建脚本" -ForegroundColor Green
    Write-Host "========================"

    # 检查 Go 版本（>= 1.22）
    $goVerRaw = (go version) 2>$null
    if (-not $goVerRaw) {
        Write-Host "未检测到 Go，请先安装 Go 1.22+" -ForegroundColor Red
        exit 1
    }
    $m = [regex]::Match($goVerRaw, 'go(\d+)\.(\d+)')
    if (-not $m.Success) {
        Write-Host "无法解析 Go 版本: $goVerRaw" -ForegroundColor Red
        exit 1
    }
    $maj = [int]$m.Groups[1].Value
    $min = [int]$m.Groups[2].Value
    if ($maj -lt 1 -or ($maj -eq 1 -and $min -lt 22)) {
        Write-Host "需要 Go >= 1.22，当前: $goVerRaw" -ForegroundColor Red
        exit 1
    }
    Write-Host "Go 版本满足要求: $goVerRaw" -ForegroundColor Green

    # 获取版本信息
    $VERSION = (go run ./scripts/version)
    if ([string]::IsNullOrWhiteSpace($VERSION)) {
        $VERSION = "dev"
    }
    $BUILD_TIME = Get-Date -Format "yyyy-MM-dd_HH:mm:ss"
    $COMMIT_HASH = "unknown"

# 尝试获取git提交哈希
if (Get-Command git -ErrorAction SilentlyContinue) {
    try {
        $COMMIT_HASH = git rev-parse --short HEAD 2>$null
        if (-not $COMMIT_HASH) {
            $COMMIT_HASH = "unknown"
        }
    } catch {
        $COMMIT_HASH = "unknown"
    }
}

# 创建输出目录
if (-not (Test-Path "bin")) {
    New-Item -ItemType Directory -Path "bin" | Out-Null
}

# 清理旧文件
if (Test-Path "bin\gencert-*") {
    Remove-Item "bin\gencert-*" -Force
}

Write-Host "版本: $VERSION"
Write-Host "构建时间: $BUILD_TIME"
Write-Host "提交哈希: $COMMIT_HASH"
Write-Host "========================"

# 构建平台配置
$platforms = @(
    @{ OS = "windows"; Arch = "amd64"; Output = "gencert-windows-amd64.exe" },
    @{ OS = "linux"; Arch = "amd64"; Output = "gencert-linux-amd64" },
    @{ OS = "darwin"; Arch = "amd64"; Output = "gencert-macos-amd64" },
    @{ OS = "darwin"; Arch = "arm64"; Output = "gencert-macos-arm64" }
)

# 构建每个平台
foreach ($platform in $platforms) {
    Write-Host "构建 $($platform.OS)/$($platform.Arch)..."

    $env:GOOS = $platform.OS
    $env:GOARCH = $platform.Arch
    $env:CGO_ENABLED = "0"

    $ldflags = "-X 'github.com/formzs/gencert/internal/version.Version=$VERSION' -X 'github.com/formzs/gencert/internal/version.BuildTime=$BUILD_TIME' -X 'github.com/formzs/gencert/internal/version.CommitHash=$COMMIT_HASH'"

    try {
        go build -ldflags="$ldflags" -o "bin\$($platform.Output)" ./cmd/gencert
        Write-Host "✓ 构建完成: bin\$($platform.Output)" -ForegroundColor Green
    } catch {
        Write-Host "✗ 构建失败: bin\$($platform.Output)" -ForegroundColor Red
    }
}

    Write-Host "========================"
    Write-Host "构建完成！" -ForegroundColor Green
    Write-Host "输出目录: bin\" 

    # 显示构建结果
    $artifacts = Get-ChildItem "bin\gencert-*" -File | Sort-Object Name
    foreach ($f in $artifacts) {
        Write-Host $f.Name -ForegroundColor Cyan
    }

    # 生成 SHA256 校验和（兼容旧版 PowerShell 无 Get-FileHash 的场景）
    Write-Host ""; Write-Host "创建校验和文件..." -ForegroundColor Yellow
    $hashLines = @()
    $hasGetFileHash = Get-Command Get-FileHash -ErrorAction SilentlyContinue
    foreach ($f in $artifacts) {
        $hash = $null
        if ($hasGetFileHash) {
            $h = Get-FileHash -Algorithm SHA256 -Path $f.FullName
            $hash = $h.Hash
        } else {
            $out = & certutil -hashfile $f.FullName SHA256 2>$null
            if ($LASTEXITCODE -eq 0 -and $out) {
                $line = ($out | Where-Object { $_ -match '^[0-9A-Fa-f]+$' } | Select-Object -First 1)
                if ($line) { $hash = $line.Trim() }
            }
        }
        if ($null -ne $hash -and $hash -ne '') {
            $hashLines += ("{0}  {1}" -f $hash.ToUpper(), $f.Name)
        }
    }
    if ($hashLines.Count -gt 0) {
        $hashLines -join "`n" | Out-File -Encoding ascii -FilePath "bin\sha256sums.txt"
        Write-Host "校验和文件: bin\sha256sums.txt" -ForegroundColor Green
    } else {
        Write-Host "跳过校验和生成（缺少支持命令）" -ForegroundColor Yellow
    }

    Write-Host ""; Write-Host "PowerShell构建脚本执行完成！" -ForegroundColor Green
}
finally {
    Pop-Location
}
