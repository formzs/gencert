package utils

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// EnsureDir 确保目录存在
func EnsureDir(path string) error {
	return os.MkdirAll(path, 0755)
}

// FileExists 检查文件是否存在
func FileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// GenerateSerialNumber 生成序列号
func GenerateSerialNumber() *big.Int {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		// 如果随机数生成失败，使用时间戳作为后备方案
		return big.NewInt(time.Now().Unix())
	}
	return serial
}

// SavePEMFile 保存PEM格式文件
func SavePEMFile(path string, pemType string, data []byte) error {
	// 确保目录存在
	if err := EnsureDir(filepath.Dir(path)); err != nil {
		return err
	}

	// 创建PEM块
	block := &pem.Block{
		Type:  pemType,
		Bytes: data,
	}

	// 写入文件
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	return pem.Encode(file, block)
}

// LoadPEMFile 加载PEM格式文件
func LoadPEMFile(path string, pemType string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取文件失败: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("解析PEM失败")
	}

	if block.Type != pemType {
		return nil, fmt.Errorf("PEM类型不匹配，期望: %s，实际: %s", pemType, block.Type)
	}

	return block.Bytes, nil
}

// LoadPrivateKey 加载私钥
func LoadPrivateKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取私钥文件失败: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("解析PEM私钥失败")
	}

	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// LoadCertificate 加载证书
func LoadCertificate(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取证书文件失败: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("解析PEM证书失败")
	}

	return x509.ParseCertificate(block.Bytes)
}

// CreateCertificateChain 创建证书链
func CreateCertificateChain(certPaths []string, outputPath string) error {
	// 确保目录存在
	if err := EnsureDir(filepath.Dir(outputPath)); err != nil {
		return err
	}

	// 创建输出文件
	outputFile, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer outputFile.Close()

	// 逐个添加证书
	for _, certPath := range certPaths {
		data, err := os.ReadFile(certPath)
		if err != nil {
			return fmt.Errorf("读取证书文件 %s 失败: %w", certPath, err)
		}

		// 写入证书数据
		if _, err := outputFile.Write(data); err != nil {
			return fmt.Errorf("写入证书数据失败: %w", err)
		}

		// 添加换行符
		if _, err := outputFile.WriteString("\n"); err != nil {
			return fmt.Errorf("写入换行符失败: %w", err)
		}
	}

	return nil
}

var invalidFilenameChars = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)

// SanitizeDomainForFilename 将域名转换为文件名安全的片段
func SanitizeDomainForFilename(domain string) string {
	if domain == "" {
		return "domain"
	}

	replacement := invalidFilenameChars.ReplaceAllStringFunc(domain, func(segment string) string {
		if segment == "*" {
			return "_wildcard_"
		}
		return "_"
	})

	replacement = strings.Trim(replacement, "._")
	if replacement == "" {
		return "domain"
	}

	return replacement
}
