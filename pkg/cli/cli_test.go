package cli

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/formzs/gencert/internal/config"
	"github.com/formzs/gencert/internal/crypto"
	"github.com/formzs/gencert/internal/logger"
	"github.com/formzs/gencert/internal/utils"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunGenerateCertificates_MultipleDomains(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "gencert-cli-test")
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
		OrgUnit:      "QA",
		CommonName:   "test.local",
		DefaultBits:  1024,
		DefaultDays:  365,
		PKCS12: config.PKCS12Config{
			DefaultPassword: config.DefaultPKCS12Password,
			FriendlyName:    config.DefaultPKCS12FriendlyName,
		},
	}

	log := logger.New(true)

	cmd := &cobra.Command{Use: "generate"}
	cmd.Flags().StringSlice("san", nil, "")
	require.NoError(t, cmd.Flags().Set("san", "api.test.local,admin.test.local"))

	domains := []string{"example.local", "example.internal"}
	err = runGenerateCertificates(cfg, log, cmd, domains)
	require.NoError(t, err)

	for _, domain := range domains {
		assert.FileExists(t, filepath.Join(cfg.CertDir, domain+".crt"))
		assert.FileExists(t, filepath.Join(cfg.CertDir, domain+".key"))
		assert.FileExists(t, filepath.Join(cfg.CertDir, domain+"-client.crt"))
		assert.FileExists(t, filepath.Join(cfg.CertDir, domain+"-client.key"))

		cert := loadCertificate(t, filepath.Join(cfg.CertDir, domain+".crt"))
		assert.Contains(t, cert.DNSNames, "api.test.local")
		assert.Contains(t, cert.DNSNames, "admin.test.local")
		assert.Contains(t, cert.DNSNames, domain)
	}
}

func TestRunGenerateCertificates_WildcardDomain(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "gencert-cli-wildcard")
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
		OrgUnit:      "QA",
		CommonName:   "test.local",
		DefaultBits:  1024,
		DefaultDays:  365,
		PKCS12: config.PKCS12Config{
			DefaultPassword: config.DefaultPKCS12Password,
			FriendlyName:    config.DefaultPKCS12FriendlyName,
		},
	}

	log := logger.New(true)

	cmd := &cobra.Command{Use: "generate"}
	cmd.Flags().StringSlice("san", nil, "")

	domain := "*.example.com"
	require.NoError(t, runGenerateCertificates(cfg, log, cmd, []string{domain}))

	safeDomain := utils.SanitizeDomainForFilename(domain)
	serverCert := filepath.Join(cfg.CertDir, safeDomain+".crt")
	clientP12 := filepath.Join(cfg.CertDir, safeDomain+"-client.p12")
	assert.FileExists(t, serverCert)
	assert.FileExists(t, clientP12)

	certBytes, err := os.ReadFile(serverCert)
	require.NoError(t, err)
	block, _ := pem.Decode(certBytes)
	require.NotNil(t, block)
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	assert.Contains(t, cert.DNSNames, domain)
}

func TestPKCS12ChangePasswordCommand(t *testing.T) {
	cfg, log, p12Path := setupPKCS12CommandTest(t, "change.example.com")
	cmd := newPKCS12Command(cfg, log)
	output := executeCommand(t, cmd, "change-password", "--input", p12Path, "--new", "NewPass123!")
	assert.Contains(t, output, "已更新 PKCS12 密码")

	pm := crypto.NewPKCS12Manager(cfg, log)
	_, _, _, _, err := pm.LoadPKCS12Bundle(p12Path, cfg.PKCS12.DefaultPassword)
	assert.Error(t, err)
	_, _, _, _, err = pm.LoadPKCS12Bundle(p12Path, "NewPass123!")
	assert.NoError(t, err)
}

func TestPKCS12InfoCommand(t *testing.T) {
	cfg, log, p12Path := setupPKCS12CommandTest(t, "info.example.com")
	cmd := newPKCS12Command(cfg, log)
	output := executeCommand(t, cmd, "info", "--input", p12Path, "--password", cfg.PKCS12.DefaultPassword)
	assert.Contains(t, output, "友好名称")
	assert.Contains(t, output, "info.example.com")
}

func loadCertificate(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)

	block, _ := pem.Decode(data)
	require.NotNil(t, block)

	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	return cert
}

func setupPKCS12CommandTest(t *testing.T, domain string) (*config.Config, logger.Logger, string) {
	t.Helper()
	tempDir := t.TempDir()
	cfg := &config.Config{
		RootCADir:    filepath.Join(tempDir, "ca"),
		CertDir:      filepath.Join(tempDir, "certs"),
		LogDir:       filepath.Join(tempDir, "logs"),
		Country:      "CN",
		State:        "Shanghai",
		Locality:     "Hongqiao",
		Organization: "Test Org",
		OrgUnit:      "QA",
		CommonName:   domain,
		DefaultBits:  1024,
		DefaultDays:  365,
		PKCS12: config.PKCS12Config{
			DefaultPassword: config.DefaultPKCS12Password,
			FriendlyName:    config.DefaultPKCS12FriendlyName,
		},
	}
	log := logger.New(true)
	certMgr := crypto.NewCertificateManager(cfg, log)
	require.NoError(t, certMgr.GenerateRootCA())
	require.NoError(t, certMgr.GenerateCertificates(domain, nil))
	pkcs12Mgr := crypto.NewPKCS12Manager(cfg, log)
	require.NoError(t, pkcs12Mgr.CreateClientBundle(domain))
	safe := utils.SanitizeDomainForFilename(domain)
	return cfg, log, filepath.Join(cfg.CertDir, safe+"-client.p12")
}

func executeCommand(t *testing.T, cmd *cobra.Command, args ...string) string {
	t.Helper()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs(args)
	cmd.SilenceUsage = true
	require.NoError(t, cmd.Execute())
	return buf.String()
}
