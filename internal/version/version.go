package version

import (
	"fmt"
	"runtime"
)

// 默认版本信息
const DefaultVersion = "1.2.0"

// 版本信息
var (
	Version    = DefaultVersion
	BuildTime  = "unknown"
	CommitHash = "unknown"
)

// GetVersionInfo 获取版本信息
func GetVersionInfo() string {
	return fmt.Sprintf("GenCert %s\n构建时间: %s\n提交哈希: %s\nGo版本: %s\n操作系统: %s/%s",
		Version, BuildTime, CommitHash, runtime.Version(), runtime.GOOS, runtime.GOARCH)
}

// PrintVersion 打印版本信息
func PrintVersion() {
	fmt.Println("GenCert - 证书生成")
	fmt.Printf("版本: %s\n", Version)
	fmt.Printf("构建时间: %s\n", BuildTime)
	fmt.Printf("提交哈希: %s\n", CommitHash)
	fmt.Printf("Go版本: %s\n", runtime.Version())
	fmt.Printf("操作系统: %s/%s\n", runtime.GOOS, runtime.GOARCH)
}
