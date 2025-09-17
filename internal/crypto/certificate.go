package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/formzs/gencert/internal/config"
	"github.com/formzs/gencert/internal/logger"
	"github.com/formzs/gencert/internal/utils"
)

// CertificateManager 证书管理器
type CertificateManager struct {
	config    *config.Config
	logger    logger.Logger
	caMgr     *CAManager
	pkcs12Mgr *PKCS12Manager
}

// NewCertificateManager 创建证书管理器
func NewCertificateManager(cfg *config.Config, log logger.Logger) *CertificateManager {
	return &CertificateManager{
		config:    cfg,
		logger:    log,
		caMgr:     NewCAManager(cfg, log),
		pkcs12Mgr: NewPKCS12Manager(cfg, log),
	}
}

// GenerateRootCA 生成根CA证书
func (cm *CertificateManager) GenerateRootCA() error {
	return cm.caMgr.GenerateRootCA()
}

// GenerateCertificates 生成服务器和客户端证书
func (cm *CertificateManager) GenerateCertificates(domain string, altDomains []string) error {
	cm.logger.Info("开始生成证书", logger.Str("domain", domain))

	// 加载根CA
	rootCert, rootKey, err := cm.caMgr.LoadRootCA()
	if err != nil {
		return fmt.Errorf("加载根CA失败: %w", err)
	}

	// 生成服务器证书
	if err := cm.generateServerCertificate(domain, altDomains, rootCert, rootKey); err != nil {
		return fmt.Errorf("生成服务器证书失败: %w", err)
	}

	// 生成客户端证书
	if err := cm.generateClientCertificate(domain, rootCert, rootKey); err != nil {
		return fmt.Errorf("生成客户端证书失败: %w", err)
	}

	// 生成证书链
	if err := cm.generateCertificateChains(domain); err != nil {
		return fmt.Errorf("生成证书链失败: %w", err)
	}

	// 创建客户端证书包
	if err := cm.pkcs12Mgr.CreateClientBundle(domain); err != nil {
		return fmt.Errorf("创建客户端证书包失败: %w", err)
	}

	cm.logger.Info("证书生成完成")
	return nil
}

// generateServerCertificate 生成服务器证书
func (cm *CertificateManager) generateServerCertificate(domain string, altDomains []string, rootCert *x509.Certificate, rootKey *rsa.PrivateKey) error {
	cm.logger.Info("生成服务器证书", logger.Str("domain", domain))

	// 生成服务器私钥
	serverKey, err := rsa.GenerateKey(rand.Reader, cm.config.DefaultBits)
	if err != nil {
		return fmt.Errorf("生成服务器私钥失败: %w", err)
	}

	// 保存服务器私钥
	fileSafeDomain := utils.SanitizeDomainForFilename(domain)
	serverKeyPath := filepath.Join(cm.config.CertDir, fmt.Sprintf("%s.key", fileSafeDomain))
	if err := cm.caMgr.savePrivateKey(serverKey, serverKeyPath); err != nil {
		return err
	}

	// 创建证书模板
	subject := cm.config.GetSubject()
	subject["commonName"] = domain
	template := &x509.Certificate{
		SerialNumber:          utils.GenerateSerialNumber(),
		Subject:               cm.caMgr.createSubject(subject),
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Duration(cm.config.DefaultDays) * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	// 添加SAN扩展
	if err := cm.addSANExtension(template, domain, altDomains); err != nil {
		return fmt.Errorf("添加SAN扩展失败: %w", err)
	}

	// 使用根CA签发证书
	certDER, err := x509.CreateCertificate(rand.Reader, template, rootCert, &serverKey.PublicKey, rootKey)
	if err != nil {
		return fmt.Errorf("签发服务器证书失败: %w", err)
	}

	// 保存服务器证书
	serverCertPath := filepath.Join(cm.config.CertDir, fmt.Sprintf("%s.crt", fileSafeDomain))
	if err := cm.caMgr.saveCertificate(certDER, serverCertPath); err != nil {
		return err
	}

	cm.logger.Info("服务器证书生成完成", logger.Str("domain", domain))
	return nil
}

// generateClientCertificate 生成客户端证书
func (cm *CertificateManager) generateClientCertificate(domain string, rootCert *x509.Certificate, rootKey *rsa.PrivateKey) error {
	cm.logger.Info("生成客户端证书", logger.Str("domain", domain))

	// 生成客户端私钥
	clientKey, err := rsa.GenerateKey(rand.Reader, cm.config.DefaultBits)
	if err != nil {
		return fmt.Errorf("生成客户端私钥失败: %w", err)
	}

	// 保存客户端私钥
	fileSafeDomain := utils.SanitizeDomainForFilename(domain)
	clientKeyPath := filepath.Join(cm.config.CertDir, fmt.Sprintf("%s-client.key", fileSafeDomain))
	if err := cm.caMgr.savePrivateKey(clientKey, clientKeyPath); err != nil {
		return err
	}

	// 创建证书模板
	subject := cm.config.GetSubject()
	subject["commonName"] = fmt.Sprintf("%s-client", domain)
	subject["organizationalUnit"] = "Client"
	template := &x509.Certificate{
		SerialNumber:          utils.GenerateSerialNumber(),
		Subject:               cm.caMgr.createSubject(subject),
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Duration(cm.config.DefaultDays) * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	// 使用根CA签发证书
	certDER, err := x509.CreateCertificate(rand.Reader, template, rootCert, &clientKey.PublicKey, rootKey)
	if err != nil {
		return fmt.Errorf("签发客户端证书失败: %w", err)
	}

	// 保存客户端证书
	clientCertPath := filepath.Join(cm.config.CertDir, fmt.Sprintf("%s-client.crt", fileSafeDomain))
	if err := cm.caMgr.saveCertificate(certDER, clientCertPath); err != nil {
		return err
	}

	cm.logger.Info("客户端证书生成完成", logger.Str("domain", domain))
	return nil
}

// addSANExtension 添加SAN扩展
func (cm *CertificateManager) addSANExtension(template *x509.Certificate, domain string, altDomains []string) error {
	// 创建DNS名称列表
	dnsNames := []string{domain}
	for _, altDomain := range altDomains {
		dnsNames = append(dnsNames, altDomain)
	}

	// 设置DNSNames字段，Go的x509包会自动处理SAN扩展
	template.DNSNames = dnsNames
	cm.logger.Debug("设置SAN扩展", logger.Str("dns_names", fmt.Sprintf("%v", dnsNames)))

	return nil
}

// generateCertificateChains 生成证书链
func (cm *CertificateManager) generateCertificateChains(domain string) error {
	cm.logger.Info("生成证书链", logger.Str("domain", domain))

	// 服务器证书链
	fileSafeDomain := utils.SanitizeDomainForFilename(domain)
	serverCertPath := filepath.Join(cm.config.CertDir, fmt.Sprintf("%s.crt", fileSafeDomain))
	rootCertPath := fmt.Sprintf("%s/rootCA.crt", cm.config.RootCADir)
	serverChainPath := filepath.Join(cm.config.CertDir, fmt.Sprintf("%s-chain.pem", fileSafeDomain))

	if err := cm.createChainFile([]string{serverCertPath, rootCertPath}, serverChainPath); err != nil {
		return fmt.Errorf("生成服务器证书链失败: %w", err)
	}

	// 客户端证书链
	clientCertPath := filepath.Join(cm.config.CertDir, fmt.Sprintf("%s-client.crt", fileSafeDomain))
	clientChainPath := filepath.Join(cm.config.CertDir, fmt.Sprintf("%s-client-chain.pem", fileSafeDomain))

	if err := cm.createChainFile([]string{clientCertPath, rootCertPath}, clientChainPath); err != nil {
		return fmt.Errorf("生成客户端证书链失败: %w", err)
	}

	cm.logger.Info("证书链生成完成", logger.Str("domain", domain))
	return nil
}

// createChainFile 创建证书链文件
func (cm *CertificateManager) createChainFile(certPaths []string, outputPath string) error {
	outputFile, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer outputFile.Close()

	for _, certPath := range certPaths {
		certBytes, err := os.ReadFile(certPath)
		if err != nil {
			return fmt.Errorf("读取证书文件失败 %s: %w", certPath, err)
		}

		// 写入原始PEM内容
		if _, err := outputFile.Write(certBytes); err != nil {
			return fmt.Errorf("写入证书链失败: %w", err)
		}

		// 添加换行符分隔
		if _, err := outputFile.WriteString("\n"); err != nil {
			return fmt.Errorf("写入分隔符失败: %w", err)
		}
	}

	return nil
}
