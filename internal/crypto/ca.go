package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/formzs/gencert/internal/config"
	"github.com/formzs/gencert/internal/logger"
)

// CAManager CA管理器
type CAManager struct {
	config *config.Config
	logger logger.Logger
}

// NewCAManager 创建CA管理器
func NewCAManager(cfg *config.Config, log logger.Logger) *CAManager {
	return &CAManager{
		config: cfg,
		logger: log,
	}
}

// GenerateRootCA 生成根CA证书
func (cm *CAManager) GenerateRootCA() error {
	rootCAKeyPath := fmt.Sprintf("%s/rootCA.key", cm.config.RootCADir)
	rootCACertPath := fmt.Sprintf("%s/rootCA.crt", cm.config.RootCADir)

	// 检查根CA是否已存在
	if _, err := os.Stat(rootCAKeyPath); err == nil {
		if _, err := os.Stat(rootCACertPath); err == nil {
			cm.logger.Info("根CA已存在，跳过生成")
			return nil
		}
	}

	cm.logger.Info("开始生成根CA证书")

	// 生成私钥
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return fmt.Errorf("生成私钥失败: %w", err)
	}

	// 创建证书模板
	subject := cm.config.GetRootCASubject()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               cm.createSubject(subject),
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0), // 10年有效期
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}

	// 自签名证书
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("创建证书失败: %w", err)
	}

	// 保存私钥
	if err := cm.savePrivateKey(privateKey, rootCAKeyPath); err != nil {
		return fmt.Errorf("保存私钥失败: %w", err)
	}

	// 保存证书
	if err := cm.saveCertificate(certDER, rootCACertPath); err != nil {
		return fmt.Errorf("保存证书失败: %w", err)
	}

	cm.logger.Info("根CA生成完成", logger.Str("path", cm.config.RootCADir))
	return nil
}

// createSubject 创建证书主题
func (cm *CAManager) createSubject(subject map[string]string) pkix.Name {
	return pkix.Name{
		Country:            []string{subject["country"]},
		Province:           []string{subject["state"]},
		Locality:           []string{subject["locality"]},
		Organization:       []string{subject["organization"]},
		OrganizationalUnit: []string{subject["organizationalUnit"]},
		CommonName:         subject["commonName"],
	}
}

// savePrivateKey 保存私钥
func (cm *CAManager) savePrivateKey(privateKey *rsa.PrivateKey, path string) error {
	// 确保目录存在
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("创建私钥目录失败: %w", err)
	}

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}

	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("创建私钥文件失败: %w", err)
	}
	defer file.Close()

	return pem.Encode(file, privateKeyPEM)
}

// saveCertificate 保存证书
func (cm *CAManager) saveCertificate(certDER []byte, path string) error {
	// 确保目录存在
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("创建证书目录失败: %w", err)
	}

	certPEM := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	}

	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("创建证书文件失败: %w", err)
	}
	defer file.Close()

	return pem.Encode(file, certPEM)
}

// LoadRootCA 加载根CA证书和私钥
func (cm *CAManager) LoadRootCA() (*x509.Certificate, *rsa.PrivateKey, error) {
	rootCAKeyPath := fmt.Sprintf("%s/rootCA.key", cm.config.RootCADir)
	rootCACertPath := fmt.Sprintf("%s/rootCA.crt", cm.config.RootCADir)

	// 检查文件是否存在
	if _, err := os.Stat(rootCAKeyPath); os.IsNotExist(err) {
		return nil, nil, fmt.Errorf("根CA私钥不存在: %s", rootCAKeyPath)
	}
	if _, err := os.Stat(rootCACertPath); os.IsNotExist(err) {
		return nil, nil, fmt.Errorf("根CA证书不存在: %s", rootCACertPath)
	}

	// 读取私钥
	privateKeyBytes, err := os.ReadFile(rootCAKeyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("读取私钥失败: %w", err)
	}

	privateKeyPEM, _ := pem.Decode(privateKeyBytes)
	if privateKeyPEM == nil {
		return nil, nil, fmt.Errorf("解析私钥PEM失败")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(privateKeyPEM.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("解析私钥失败: %w", err)
	}

	// 读取证书
	certBytes, err := os.ReadFile(rootCACertPath)
	if err != nil {
		return nil, nil, fmt.Errorf("读取证书失败: %w", err)
	}

	certPEM, _ := pem.Decode(certBytes)
	if certPEM == nil {
		return nil, nil, fmt.Errorf("解析证书PEM失败")
	}

	cert, err := x509.ParseCertificate(certPEM.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("解析证书失败: %w", err)
	}

	return cert, privateKey, nil
}
