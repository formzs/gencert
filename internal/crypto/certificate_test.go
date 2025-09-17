package crypto

import (
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/formzs/gencert/internal/config"
	"github.com/formzs/gencert/internal/logger"
	"github.com/formzs/gencert/internal/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCertificateManager_GenerateRootCA(t *testing.T) {
	// 创建临时目录
	tempDir, err := os.MkdirTemp("", "gencert-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// 创建配置
	cfg := &config.Config{
		RootCADir:    filepath.Join(tempDir, "ca"),
		CertDir:      filepath.Join(tempDir, "certs"),
		LogDir:       filepath.Join(tempDir, "logs"),
		Country:      "CN",
		State:        "Shanghai",
		Locality:     "Hongqiao",
		Organization: "Test Org",
		OrgUnit:      "Test Unit",
		CommonName:   "test.com",
		DefaultBits:  2048,
		DefaultDays:  365,
	}

	// 创建日志
	log := logger.New(true)

	// 创建证书管理器
	certMgr := NewCertificateManager(cfg, log)

	// 生成根CA
	err = certMgr.GenerateRootCA()
	require.NoError(t, err)

	// 验证文件存在
	assert.FileExists(t, filepath.Join(cfg.RootCADir, "rootCA.key"))
	assert.FileExists(t, filepath.Join(cfg.RootCADir, "rootCA.crt"))
}

func TestCertificateManager_GenerateCertificates(t *testing.T) {
	// 创建临时目录
	tempDir, err := os.MkdirTemp("", "gencert-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// 创建配置
	cfg := &config.Config{
		RootCADir:    filepath.Join(tempDir, "ca"),
		CertDir:      filepath.Join(tempDir, "certs"),
		LogDir:       filepath.Join(tempDir, "logs"),
		Country:      "CN",
		State:        "Shanghai",
		Locality:     "Hongqiao",
		Organization: "Test Org",
		OrgUnit:      "Test Unit",
		CommonName:   "test.com",
		DefaultBits:  2048,
		DefaultDays:  365,
	}

	// 创建日志
	log := logger.New(true)

	// 创建证书管理器
	certMgr := NewCertificateManager(cfg, log)

	// 生成根CA
	err = certMgr.GenerateRootCA()
	require.NoError(t, err)

	// 生成证书
	domain := "test.example.com"
	altDomains := []string{"api.test.example.com", "admin.test.example.com"}
	err = certMgr.GenerateCertificates(domain, altDomains)
	require.NoError(t, err)

	safeDomain := utils.SanitizeDomainForFilename(domain)

	// 验证服务器证书文件存在
	assert.FileExists(t, filepath.Join(cfg.CertDir, safeDomain+".key"))
	assert.FileExists(t, filepath.Join(cfg.CertDir, safeDomain+".crt"))
	assert.FileExists(t, filepath.Join(cfg.CertDir, safeDomain+"-chain.pem"))

	// 验证客户端证书文件存在
	assert.FileExists(t, filepath.Join(cfg.CertDir, safeDomain+"-client.key"))
	assert.FileExists(t, filepath.Join(cfg.CertDir, safeDomain+"-client.crt"))
	assert.FileExists(t, filepath.Join(cfg.CertDir, safeDomain+"-client-chain.pem"))
	assert.FileExists(t, filepath.Join(cfg.CertDir, safeDomain+"-client.p12"))
}

func TestCertificateManager_GenerateCertificates_Wildcard(t *testing.T) {
	// 创建临时目录
	tempDir, err := os.MkdirTemp("", "gencert-wildcard")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	cfg := &config.Config{
		RootCADir:    filepath.Join(tempDir, "ca"),
		CertDir:      filepath.Join(tempDir, "certs"),
		LogDir:       filepath.Join(tempDir, "logs"),
		Country:      "CN",
		State:        "Shanghai",
		Locality:     "Hongqiao",
		Organization: "Test Org",
		OrgUnit:      "Test Unit",
		CommonName:   "test.com",
		DefaultBits:  2048,
		DefaultDays:  365,
	}

	log := logger.New(true)
	certMgr := NewCertificateManager(cfg, log)
	require.NoError(t, certMgr.GenerateRootCA())

	domain := "*.example.com"
	altDomains := []string{"api.example.com"}
	require.NoError(t, certMgr.GenerateCertificates(domain, altDomains))

	safeDomain := utils.SanitizeDomainForFilename(domain)
	serverCertPath := filepath.Join(cfg.CertDir, safeDomain+".crt")
	assert.FileExists(t, serverCertPath)

	certBytes, err := os.ReadFile(serverCertPath)
	require.NoError(t, err)
	block, _ := pem.Decode(certBytes)
	require.NotNil(t, block)
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	assert.Equal(t, domain, cert.Subject.CommonName)
	assert.Contains(t, cert.DNSNames, domain)
	assert.Contains(t, cert.DNSNames, altDomains[0])
}

func TestCertificateManager_addSANExtension(t *testing.T) {
	// 创建临时目录
	tempDir, err := os.MkdirTemp("", "gencert-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// 创建配置
	cfg := &config.Config{
		RootCADir:    filepath.Join(tempDir, "ca"),
		CertDir:      filepath.Join(tempDir, "certs"),
		LogDir:       filepath.Join(tempDir, "logs"),
		Country:      "CN",
		State:        "Shanghai",
		Locality:     "Hongqiao",
		Organization: "Test Org",
		OrgUnit:      "Test Unit",
		CommonName:   "test.com",
	}

	// 创建日志
	log := logger.New(true)

	// 创建证书管理器
	certMgr := NewCertificateManager(cfg, log)

	// 创建证书模板
	template := &x509.Certificate{
		SerialNumber: big.NewInt(123456789),
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(1, 0, 0),
	}

	// 添加SAN扩展
	domain := "test.example.com"
	altDomains := []string{"api.test.example.com", "admin.test.example.com"}
	err = certMgr.addSANExtension(template, domain, altDomains)
	require.NoError(t, err)

	// 验证DNS名称
	assert.Len(t, template.DNSNames, 3)
	assert.Contains(t, template.DNSNames, "test.example.com")
	assert.Contains(t, template.DNSNames, "api.test.example.com")
	assert.Contains(t, template.DNSNames, "admin.test.example.com")
}

func TestCertificateManager_addSANExtension_WithIPv4(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "gencert-test-ip")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	cfg := &config.Config{
		RootCADir:    filepath.Join(tempDir, "ca"),
		CertDir:      filepath.Join(tempDir, "certs"),
		LogDir:       filepath.Join(tempDir, "logs"),
		Country:      "CN",
		State:        "Shanghai",
		Locality:     "Hongqiao",
		Organization: "Test Org",
		OrgUnit:      "Test Unit",
		CommonName:   "test.com",
	}

	log := logger.New(true)
	certMgr := NewCertificateManager(cfg, log)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(987654321),
		Subject:      pkix.Name{CommonName: "192.168.1.10"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
	}

	domain := "192.168.1.10"
	alt := []string{"10.0.0.2", "svc.internal"}
	err = certMgr.addSANExtension(template, domain, alt)
	require.NoError(t, err)

	// 期望：两个 IPv4 进入 IPAddresses，域名进入 DNSNames
	assert.Contains(t, template.DNSNames, "svc.internal")
	assert.NotContains(t, template.DNSNames, "192.168.1.10")
	assert.NotContains(t, template.DNSNames, "10.0.0.2")
	require.GreaterOrEqual(t, len(template.IPAddresses), 2)
}

func TestCertificateManager_generateCertificateChains(t *testing.T) {
	// 创建临时目录
	tempDir, err := os.MkdirTemp("", "gencert-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// 创建配置
	cfg := &config.Config{
		RootCADir:    filepath.Join(tempDir, "ca"),
		CertDir:      filepath.Join(tempDir, "certs"),
		LogDir:       filepath.Join(tempDir, "logs"),
		Country:      "CN",
		State:        "Shanghai",
		Locality:     "Hongqiao",
		Organization: "Test Org",
		OrgUnit:      "Test Unit",
		CommonName:   "test.com",
	}

	// 创建日志
	log := logger.New(true)

	// 创建证书管理器
	certMgr := NewCertificateManager(cfg, log)

	// 创建测试证书
	testDomain := "test.example.com"

	// 创建服务器证书
	serverCert := &x509.Certificate{
		SerialNumber: big.NewInt(123456789),
		Subject: pkix.Name{
			CommonName: testDomain,
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(1, 0, 0),
	}

	// 创建根CA证书
	rootCert := &x509.Certificate{
		SerialNumber: big.NewInt(987654321),
		Subject: pkix.Name{
			CommonName: "Test Root CA",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(10, 0, 0),
		IsCA:      true,
	}

	// 保存测试证书
	serverCertPath := filepath.Join(cfg.CertDir, testDomain+".crt")
	clientCertPath := filepath.Join(cfg.CertDir, testDomain+"-client.crt")
	rootCertPath := filepath.Join(cfg.RootCADir, "rootCA.crt")

	saveTestCertificate(t, serverCert, serverCertPath)
	saveTestCertificate(t, serverCert, clientCertPath) // 客户端证书也使用服务器证书
	saveTestCertificate(t, rootCert, rootCertPath)

	// 生成证书链
	err = certMgr.generateCertificateChains(testDomain)
	require.NoError(t, err)

	// 验证证书链文件存在
	assert.FileExists(t, filepath.Join(cfg.CertDir, testDomain+"-chain.pem"))
	assert.FileExists(t, filepath.Join(cfg.CertDir, testDomain+"-client-chain.pem"))
}

func TestCertificateManager_createChainFile(t *testing.T) {
	// 创建临时目录
	tempDir, err := os.MkdirTemp("", "gencert-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// 创建测试证书
	testDomain := "test.example.com"

	// 创建服务器证书
	serverCert := &x509.Certificate{
		SerialNumber: big.NewInt(123456789),
		Subject: pkix.Name{
			CommonName: testDomain,
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(1, 0, 0),
	}

	// 创建根CA证书
	rootCert := &x509.Certificate{
		SerialNumber: big.NewInt(987654321),
		Subject: pkix.Name{
			CommonName: "Test Root CA",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(10, 0, 0),
		IsCA:      true,
	}

	// 创建证书管理器（不需要真实配置）
	certMgr := &CertificateManager{}

	// 保存测试证书
	serverCertPath := filepath.Join(tempDir, testDomain+".crt")
	rootCertPath := filepath.Join(tempDir, "rootCA.crt")
	saveTestCertificate(t, serverCert, serverCertPath)
	saveTestCertificate(t, rootCert, rootCertPath)

	// 创建证书链文件
	chainPath := filepath.Join(tempDir, testDomain+"-chain.pem")
	certPaths := []string{serverCertPath, rootCertPath}
	err = certMgr.createChainFile(certPaths, chainPath)
	require.NoError(t, err)

	// 验证证书链文件存在且内容正确
	assert.FileExists(t, chainPath)

	// 验证文件内容
	content, err := os.ReadFile(chainPath)
	require.NoError(t, err)
	assert.Contains(t, string(content), "-----BEGIN CERTIFICATE-----")
	assert.Contains(t, string(content), "-----END CERTIFICATE-----")
}

// 辅助函数

func saveTestCertificate(t *testing.T, cert *x509.Certificate, path string) {
	// 确保目录存在
	dir := filepath.Dir(path)
	err := os.MkdirAll(dir, 0755)
	require.NoError(t, err)

	// 编码证书
	certBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	// 写入文件
	err = os.WriteFile(path, certBytes, 0644)
	require.NoError(t, err)
}

func saveTestPrivateKey(t *testing.T, path string) {
	// 生成测试私钥
	privateKey, err := rsa.GenerateKey(nil, 2048)
	require.NoError(t, err)

	// 确保目录存在
	dir := filepath.Dir(path)
	err = os.MkdirAll(dir, 0755)
	require.NoError(t, err)

	// 编码私钥
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	// 写入文件
	err = os.WriteFile(path, privateKeyPEM, 0600)
	require.NoError(t, err)
}
