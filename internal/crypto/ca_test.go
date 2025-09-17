package crypto

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/formzs/gencert/internal/config"
	"github.com/formzs/gencert/internal/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCAManager_GenerateRootCA(t *testing.T) {
	// 创建临时目录
	tempDir, err := os.MkdirTemp("", "gencert-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// 创建配置
	cfg := &config.Config{
		RootCADir:    filepath.Join(tempDir, "ca"),
		Country:      "CN",
		State:        "Shanghai",
		Locality:     "Hongqiao",
		Organization: "Test Org",
		OrgUnit:      "Test Unit",
		CommonName:   "test.com",
	}

	// 创建日志
	log := logger.New(true)

	// 创建CA管理器
	caMgr := NewCAManager(cfg, log)

	// 生成根CA
	err = caMgr.GenerateRootCA()
	require.NoError(t, err)

	// 验证文件存在
	assert.FileExists(t, filepath.Join(cfg.RootCADir, "rootCA.key"))
	assert.FileExists(t, filepath.Join(cfg.RootCADir, "rootCA.crt"))

	// 验证证书内容
	certBytes, err := os.ReadFile(filepath.Join(cfg.RootCADir, "rootCA.crt"))
	require.NoError(t, err)

	block, _ := pem.Decode(certBytes)
	require.NotNil(t, block)

	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	// 验证证书属性
	assert.True(t, cert.IsCA)
	assert.Equal(t, "Test Org Root CA", cert.Subject.CommonName)
	assert.True(t, time.Now().Before(cert.NotAfter))
}

func TestCAManager_LoadRootCA(t *testing.T) {
	// 创建临时目录
	tempDir, err := os.MkdirTemp("", "gencert-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// 创建配置
	cfg := &config.Config{
		RootCADir:    filepath.Join(tempDir, "ca"),
		Country:      "CN",
		State:        "Shanghai",
		Locality:     "Hongqiao",
		Organization: "Test Org",
		OrgUnit:      "Test Unit",
		CommonName:   "test.com",
	}

	// 创建日志
	log := logger.New(true)

	// 创建CA管理器
	caMgr := NewCAManager(cfg, log)

	// 先生成根CA
	err = caMgr.GenerateRootCA()
	require.NoError(t, err)

	// 加载根CA
	cert, key, err := caMgr.LoadRootCA()
	require.NoError(t, err)
	require.NotNil(t, cert)
	require.NotNil(t, key)

	// 验证证书属性
	assert.True(t, cert.IsCA)
	assert.Equal(t, "Test Org Root CA", cert.Subject.CommonName)
}

func TestCAManager_LoadRootCA_NotExist(t *testing.T) {
	// 创建临时目录
	tempDir, err := os.MkdirTemp("", "gencert-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// 创建配置
	cfg := &config.Config{
		RootCADir: filepath.Join(tempDir, "ca"),
	}

	// 创建日志
	log := logger.New(true)

	// 创建CA管理器
	caMgr := NewCAManager(cfg, log)

	// 尝试加载不存在的根CA
	cert, key, err := caMgr.LoadRootCA()
	require.Error(t, err)
	assert.Nil(t, cert)
	assert.Nil(t, key)
	assert.Contains(t, err.Error(), "根CA私钥不存在")
}

func TestCAManager_CreateSubject(t *testing.T) {
	// 创建配置
	cfg := &config.Config{
		Country:      "CN",
		State:        "Shanghai",
		Locality:     "Hongqiao",
		Organization: "Test Org",
		OrgUnit:      "Test Unit",
		CommonName:   "test.com",
	}

	// 创建日志
	log := logger.New(true)

	// 创建CA管理器
	caMgr := NewCAManager(cfg, log)

	// 测试创建主题
	subject := map[string]string{
		"country":            "US",
		"state":              "California",
		"locality":           "San Francisco",
		"organization":       "Another Org",
		"organizationalUnit": "Another Unit",
		"commonName":         "example.com",
	}

	pkixSubject := caMgr.createSubject(subject)

	// 验证主题属性
	assert.Equal(t, "US", pkixSubject.Country[0])
	assert.Equal(t, "California", pkixSubject.Province[0])
	assert.Equal(t, "San Francisco", pkixSubject.Locality[0])
	assert.Equal(t, "Another Org", pkixSubject.Organization[0])
	assert.Equal(t, "Another Unit", pkixSubject.OrganizationalUnit[0])
	assert.Equal(t, "example.com", pkixSubject.CommonName)
}

func TestCAManager_GenerateRootCA_AlreadyExists(t *testing.T) {
	// 创建临时目录
	tempDir, err := os.MkdirTemp("", "gencert-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// 创建配置
	cfg := &config.Config{
		RootCADir:    filepath.Join(tempDir, "ca"),
		Country:      "CN",
		State:        "Shanghai",
		Locality:     "Hongqiao",
		Organization: "Test Org",
		OrgUnit:      "Test Unit",
		CommonName:   "test.com",
	}

	// 创建日志
	log := logger.New(true)

	// 创建CA管理器
	caMgr := NewCAManager(cfg, log)

	// 第一次生成根CA
	err = caMgr.GenerateRootCA()
	require.NoError(t, err)

	// 第二次生成根CA（应该跳过）
	err = caMgr.GenerateRootCA()
	require.NoError(t, err)

	// 验证文件仍然存在
	assert.FileExists(t, filepath.Join(cfg.RootCADir, "rootCA.key"))
	assert.FileExists(t, filepath.Join(cfg.RootCADir, "rootCA.crt"))
}
