package crypto

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/formzs/gencert/internal/config"
	"github.com/formzs/gencert/internal/logger"
	"github.com/formzs/gencert/internal/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func generateTestCertificates(t *testing.T, cfg *config.Config, domain string, sans []string) {
	t.Helper()
	log := logger.New(true)
	certMgr := NewCertificateManager(cfg, log)
	require.NoError(t, certMgr.GenerateRootCA())
	require.NoError(t, certMgr.GenerateCertificates(domain, sans))
}

func newTestConfig(t *testing.T) (*config.Config, string) {
	t.Helper()
	tempDir, err := os.MkdirTemp("", "gencert-pkcs12")
	require.NoError(t, err)
	cfg := &config.Config{
		RootCADir:    filepath.Join(tempDir, "ca"),
		CertDir:      filepath.Join(tempDir, "certs"),
		LogDir:       filepath.Join(tempDir, "logs"),
		Country:      "CN",
		State:        "Shanghai",
		Locality:     "Hongqiao",
		Organization: "Test Org",
		OrgUnit:      "QA",
		CommonName:   "test.local",
		DefaultBits:  1024,
		DefaultDays:  365,
		PKCS12: config.PKCS12Config{
			DefaultPassword: config.DefaultPKCS12Password,
			FriendlyName:    config.DefaultPKCS12FriendlyName,
		},
	}
	return cfg, tempDir
}

func TestPKCS12Manager_CreatePEMBundle(t *testing.T) {
	cfg, tempDir := newTestConfig(t)
	defer os.RemoveAll(tempDir)

	domain := "test.example.com"
	generateTestCertificates(t, cfg, domain, nil)

	log := logger.New(true)
	pkcs12Mgr := NewPKCS12Manager(cfg, log)
	require.NoError(t, pkcs12Mgr.CreatePEMBundle(domain, "password123"))

	safe := utils.SanitizeDomainForFilename(domain)
	bundlePath := filepath.Join(cfg.CertDir, safe+"-client-bundle.pem")
	assert.FileExists(t, bundlePath)
}

func TestPKCS12Manager_CreateClientBundle(t *testing.T) {
	cfg, tempDir := newTestConfig(t)
	defer os.RemoveAll(tempDir)

	domain := "svc.example.com"
	generateTestCertificates(t, cfg, domain, []string{"api.example.com"})

	log := logger.New(true)
	pkcs12Mgr := NewPKCS12Manager(cfg, log)
	require.NoError(t, pkcs12Mgr.CreateClientBundle(domain))

	safe := utils.SanitizeDomainForFilename(domain)
	assert.FileExists(t, filepath.Join(cfg.CertDir, safe+"-client.p12"))
	assert.FileExists(t, filepath.Join(cfg.CertDir, safe+"-client.key"))
	assert.FileExists(t, filepath.Join(cfg.CertDir, safe+"-client.crt"))
	assert.FileExists(t, filepath.Join(cfg.CertDir, safe+"-client-chain.pem"))
}

func TestPKCS12Manager_LoadPKCS12Bundle(t *testing.T) {
	cfg, tempDir := newTestConfig(t)
	defer os.RemoveAll(tempDir)

	domain := "svc.internal"
	generateTestCertificates(t, cfg, domain, []string{"api.internal"})

	log := logger.New(true)
	pkcs12Mgr := NewPKCS12Manager(cfg, log)
	require.NoError(t, pkcs12Mgr.CreateClientBundle(domain))

	safe := utils.SanitizeDomainForFilename(domain)
	p12Path := filepath.Join(cfg.CertDir, safe+"-client.p12")
	info, cert, key, chain, err := pkcs12Mgr.LoadPKCS12Bundle(p12Path, cfg.PKCS12.DefaultPassword)
	require.NoError(t, err)
	require.NotNil(t, cert)
	require.NotNil(t, key)
	assert.GreaterOrEqual(t, len(chain), 1)
	assert.Equal(t, cfg.PKCS12.FriendlyName+" - "+domain, info.FriendlyName)
	assert.Equal(t, cert.NotBefore, info.CreatedAt)
	assert.Equal(t, cert.NotAfter, info.ExpiresAt)
	assert.Equal(t, len(chain)+1, info.CertificateCount)
}

func TestPKCS12Manager_CreateClientBundle_Wildcard(t *testing.T) {
	cfg, tempDir := newTestConfig(t)
	defer os.RemoveAll(tempDir)

	domain := "*.example.com"
	generateTestCertificates(t, cfg, domain, []string{"api.example.com"})

	log := logger.New(true)
	pkcs12Mgr := NewPKCS12Manager(cfg, log)
	keytoolAvailable := pkcs12Mgr.isKeytoolAvailable()
	require.NoError(t, pkcs12Mgr.CreateClientBundle(domain))

	safe := utils.SanitizeDomainForFilename(domain)
	assert.FileExists(t, filepath.Join(cfg.CertDir, safe+"-client.p12"))
	assert.FileExists(t, filepath.Join(cfg.CertDir, safe+"-client.key"))
	assert.FileExists(t, filepath.Join(cfg.CertDir, safe+"-client.crt"))
	assert.FileExists(t, filepath.Join(cfg.CertDir, safe+"-client-chain.pem"))
	assert.FileExists(t, filepath.Join(cfg.CertDir, safe+"-client-windows.pfx"))
	assert.FileExists(t, filepath.Join(cfg.CertDir, safe+"-client-info.txt"))
	if keytoolAvailable {
		assert.FileExists(t, filepath.Join(cfg.CertDir, safe+"-client.jks"))
		assert.FileExists(t, filepath.Join(cfg.CertDir, safe+"-truststore.jks"))
	}
}

func TestPKCS12Manager_ValidatePassword(t *testing.T) {
	cfg, tempDir := newTestConfig(t)
	defer os.RemoveAll(tempDir)

	log := logger.New(true)
	pkcs12Mgr := NewPKCS12Manager(cfg, log)

	assert.Error(t, pkcs12Mgr.validatePassword(""))
	assert.Error(t, pkcs12Mgr.validatePassword("123"))
	assert.NoError(t, pkcs12Mgr.validatePassword("validpass"))
}

func TestPKCS12Manager_CreatePKCS12BundleWithOptions(t *testing.T) {
	cfg, tempDir := newTestConfig(t)
	defer os.RemoveAll(tempDir)

	log := logger.New(true)
	pkcs12Mgr := NewPKCS12Manager(cfg, log)

	err := pkcs12Mgr.CreatePKCS12BundleWithOptions("example.com", "", &PKCS12Options{Password: ""})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "密码不能为空")

	err = pkcs12Mgr.CreatePKCS12BundleWithOptions("example.com", "short", &PKCS12Options{Password: "short"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "密码长度不能少于6个字符")
}
