package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigInit(t *testing.T) {
	// 创建临时目录
	tempDir, err := os.MkdirTemp("", "gencert-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	programDir := filepath.Join(tempDir, "app")
	require.NoError(t, os.MkdirAll(programDir, 0755))
	// 创建配置目录（位于程序目录的同级 gencert-data 下）
	configDir := filepath.Join(tempDir, "gencert-data", "configs")
	err = os.MkdirAll(configDir, 0755)
	require.NoError(t, err)

	// 创建测试配置文件
	configPath := filepath.Join(configDir, "cert.yaml")
	configContent := `
debug: true
country: US
state: California
locality: San Francisco
organization: Test Org
common_name: test.com
default_bits: 4096
default_days: 180
`
	err = os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	// 修改工作目录到临时目录
	originalDir, _ := os.Getwd()
	defer os.Chdir(originalDir)
	require.NoError(t, os.Chdir(programDir))

	// 初始化配置
	cfg, err := Init()
	require.NoError(t, err)

	// 验证配置
	assert.True(t, cfg.Debug)
	assert.Equal(t, "US", cfg.Country)
	assert.Equal(t, "California", cfg.State)
	assert.Equal(t, "San Francisco", cfg.Locality)
	assert.Equal(t, "Test Org", cfg.Organization)
	assert.Equal(t, "test.com", cfg.CommonName)
	assert.Equal(t, 4096, cfg.DefaultBits)
	assert.Equal(t, 180, cfg.DefaultDays)
	assert.Equal(t, DefaultPKCS12Password, cfg.PKCS12.DefaultPassword)
	assert.Equal(t, DefaultPKCS12FriendlyName, cfg.PKCS12.FriendlyName)
	assert.Equal(t, filepath.Join(tempDir, "gencert-data", "ca"), cfg.RootCADir)
	assert.Equal(t, filepath.Join(tempDir, "gencert-data", "certs"), cfg.CertDir)
	assert.Equal(t, filepath.Join(tempDir, "gencert-data", "logs"), cfg.LogDir)
	assert.Equal(t, configPath, cfg.ConfigFile)
}

func TestConfigDefaultValues(t *testing.T) {
	// 创建临时目录
	tempDir, err := os.MkdirTemp("", "gencert-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	programDir := filepath.Join(tempDir, "app")
	require.NoError(t, os.MkdirAll(programDir, 0755))

	// 修改工作目录到临时目录
	originalDir, _ := os.Getwd()
	defer os.Chdir(originalDir)
	require.NoError(t, os.Chdir(programDir))

	// 初始化配置（应该创建默认配置）
	cfg, err := Init()
	require.NoError(t, err)

	// 验证默认值
	assert.False(t, cfg.Debug)
	assert.Equal(t, "CN", cfg.Country)
	assert.Equal(t, "Beijing", cfg.State)
	assert.Equal(t, "ChaoYang", cfg.Locality)
	assert.Equal(t, "CA", cfg.Organization)
	assert.Equal(t, "Development", cfg.OrgUnit)
	assert.Equal(t, "Development CA", cfg.CommonName)
	assert.Equal(t, 2048, cfg.DefaultBits)
	assert.Equal(t, 3650, cfg.DefaultDays)
	assert.Equal(t, DefaultPKCS12Password, cfg.PKCS12.DefaultPassword)
	assert.Equal(t, DefaultPKCS12FriendlyName, cfg.PKCS12.FriendlyName)

	// 验证默认配置文件已创建
	assert.FileExists(t, filepath.Join(tempDir, "gencert-data", "configs", "cert.yaml"))
}

func TestGetSubject(t *testing.T) {
	cfg := &Config{
		Country:      "CN",
		State:        "Shanghai",
		Locality:     "Hongqiao",
		Organization: "Test Org",
		OrgUnit:      "Test Unit",
		CommonName:   "test.com",
	}

	subject := cfg.GetSubject()
	assert.Equal(t, "CN", subject["country"])
	assert.Equal(t, "Shanghai", subject["state"])
	assert.Equal(t, "Hongqiao", subject["locality"])
	assert.Equal(t, "Test Org", subject["organization"])
	assert.Equal(t, "Test Unit", subject["organizationalUnit"])
	assert.Equal(t, "test.com", subject["commonName"])
}

func TestGetRootCASubject(t *testing.T) {
	cfg := &Config{
		Country:      "CN",
		State:        "Shanghai",
		Locality:     "Hongqiao",
		Organization: "Test Org",
		OrgUnit:      "Test Unit",
		CommonName:   "test.com",
	}

	subject := cfg.GetRootCASubject()
	assert.Equal(t, "CN", subject["country"])
	assert.Equal(t, "Shanghai", subject["state"])
	assert.Equal(t, "Hongqiao", subject["locality"])
	assert.Equal(t, "Test Org", subject["organization"])
	assert.Equal(t, "Root CA", subject["organizationalUnit"])
	assert.Equal(t, "Test Org Root CA", subject["commonName"])
}
