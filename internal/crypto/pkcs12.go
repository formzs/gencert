package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/formzs/gencert/internal/config"
	"github.com/formzs/gencert/internal/logger"
	"github.com/formzs/gencert/internal/utils"
	"software.sslmate.com/src/go-pkcs12"
)

// PKCS12Manager PKCS12管理器
type PKCS12Manager struct {
	config *config.Config
	logger logger.Logger
}

// NewPKCS12Manager 创建PKCS12管理器
func NewPKCS12Manager(cfg *config.Config, log logger.Logger) *PKCS12Manager {
	return &PKCS12Manager{
		config: cfg,
		logger: log,
	}
}

// PKCS12Options PKCS12选项
type PKCS12Options struct {
	Password         string // 密码
	FriendlyName     string // 友好名称
	CreateForWindows bool   // 是否为Windows创建
	CreateForMac     bool   // 是否为macOS创建
	CreateForLinux   bool   // 是否为Linux创建
	IncludeChain     bool   // 是否包含证书链
}

// PKCS12Info PKCS12信息
type PKCS12Info struct {
	FriendlyName     string    // 友好名称
	CreatedAt        time.Time // 创建时间
	ExpiresAt        time.Time // 过期时间
	Subject          string    // 主题
	Issuer           string    // 签发者
	SerialNumber     string    // 序列号
	KeyAlgorithm     string    // 密钥算法
	KeySize          int       // 密钥大小
	CertificateCount int       // 证书数量
	FileSize         int64     // 文件大小
}

// CreatePKCS12Bundle 创建PKCS12格式证书包
func (pm *PKCS12Manager) CreatePKCS12Bundle(domain string, password string) error {
	if password == "" {
		password = pm.defaultPassword()
	}

	return pm.CreatePKCS12BundleWithOptions(domain, password, &PKCS12Options{
		Password:         password,
		FriendlyName:     pm.formatFriendlyName(domain),
		CreateForWindows: true,
		CreateForMac:     true,
		CreateForLinux:   true,
		IncludeChain:     true,
	})
}

// CreatePKCS12BundleWithOptions 使用选项创建PKCS12格式证书包

func (pm *PKCS12Manager) CreatePKCS12BundleWithOptions(domain string, password string, options *PKCS12Options) error {
	if options == nil {
		options = &PKCS12Options{}
	}
	if options.Password == "" {
		options.Password = password
	}
	if options.FriendlyName == "" {
		options.FriendlyName = pm.formatFriendlyName(domain)
	}
	password = options.Password

	pm.logger.Info("创建PKCS12证书包",
		logger.Str("domain", domain),
		logger.Str("friendly_name", options.FriendlyName),
		logger.Bool("include_chain", options.IncludeChain))

	// 验证密码强度
	if err := pm.validatePassword(password); err != nil {
		return fmt.Errorf("密码验证失败: %w", err)
	}

	// 确保目录存在
	if err := os.MkdirAll(pm.config.CertDir, 0755); err != nil {
		return fmt.Errorf("创建证书目录失败: %w", err)
	}

	// 读取证书和私钥
	certData, err := pm.loadCertificateData(domain)
	if err != nil {
		return fmt.Errorf("加载证书数据失败: %w", err)
	}

	// 创建PKCS12包
	pfxData, err := pm.createPKCS12Data(certData, password, options.FriendlyName, options.IncludeChain)
	if err != nil {
		return fmt.Errorf("创建PKCS12包失败: %w", err)
	}

	// 保存PKCS12文件
	fileSafeDomain := utils.SanitizeDomainForFilename(domain)
	p12Path := filepath.Join(pm.config.CertDir, fmt.Sprintf("%s-client.p12", fileSafeDomain))
	if err := os.WriteFile(p12Path, pfxData, 0600); err != nil {
		return fmt.Errorf("保存PKCS12文件失败: %w", err)
	}

	// 为不同平台创建兼容性文件
	if options.CreateForWindows {
		if err := pm.createWindowsCompatibilityFile(domain, fileSafeDomain, pfxData, password, options.FriendlyName); err != nil {
			pm.logger.Warn("创建Windows兼容文件失败", logger.Err(err))
		}
	}

	// 生成PKCS12信息文件
	if err := pm.generatePKCS12Info(domain, p12Path, options.FriendlyName, password, certData.ClientCert, certData.RootCerts); err != nil {
		pm.logger.Warn("生成PKCS12信息文件失败", logger.Err(err))
	}

	pm.logger.Info("PKCS12证书包创建完成",
		logger.Str("path", p12Path),
		logger.Int("size", len(pfxData)),
		logger.Str("friendly_name", options.FriendlyName))

	return nil
}

// CertificateData 证书数据
type CertificateData struct {
	ClientCert *x509.Certificate
	ClientKey  *rsa.PrivateKey
	RootCerts  []*x509.Certificate
}

// loadCertificateData 加载证书数据
func (pm *PKCS12Manager) loadCertificateData(domain string) (*CertificateData, error) {
	fileSafeDomain := utils.SanitizeDomainForFilename(domain)
	// 读取客户端证书和私钥
	clientCertPath := filepath.Join(pm.config.CertDir, fmt.Sprintf("%s-client.crt", fileSafeDomain))
	clientKeyPath := filepath.Join(pm.config.CertDir, fmt.Sprintf("%s-client.key", fileSafeDomain))
	rootCertPath := fmt.Sprintf("%s/rootCA.crt", pm.config.RootCADir)

	// 检查文件是否存在
	for _, path := range []string{clientCertPath, clientKeyPath, rootCertPath} {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return nil, fmt.Errorf("证书文件不存在: %s: %w", path, err)
		}
	}

	// 加载证书和私钥
	clientCert, err := pm.loadCertificate(clientCertPath)
	if err != nil {
		return nil, fmt.Errorf("加载客户端证书失败: %w", err)
	}

	clientKey, err := pm.loadPrivateKey(clientKeyPath)
	if err != nil {
		return nil, fmt.Errorf("加载客户端私钥失败: %w", err)
	}

	rootCert, err := pm.loadCertificate(rootCertPath)
	if err != nil {
		return nil, fmt.Errorf("加载根CA证书失败: %w", err)
	}

	return &CertificateData{
		ClientCert: clientCert,
		ClientKey:  clientKey,
		RootCerts:  []*x509.Certificate{rootCert},
	}, nil
}

// createPKCS12Data 创建PKCS12数据
func (pm *PKCS12Manager) createPKCS12Data(certData *CertificateData, password string, friendlyName string, includeChain bool) ([]byte, error) {
	// 创建PKCS12包
	var pfxData []byte
	var err error

	if includeChain && len(certData.RootCerts) > 0 {
		// 包含完整证书链
		pfxData, err = pkcs12.Encode(rand.Reader, certData.ClientKey, certData.ClientCert, certData.RootCerts, password)
	} else {
		// 仅包含客户端证书
		pfxData, err = pkcs12.Encode(rand.Reader, certData.ClientKey, certData.ClientCert, nil, password)
	}

	if err != nil {
		return nil, fmt.Errorf("PKCS12编码失败: %w", err)
	}

	return pfxData, nil
}

// validatePassword 验证密码强度
func (pm *PKCS12Manager) validatePassword(password string) error {
	if len(password) == 0 {
		return fmt.Errorf("密码不能为空")
	}
	if len(password) < 6 {
		return fmt.Errorf("密码长度不能少于6个字符")
	}
	return nil
}

func (pm *PKCS12Manager) defaultPassword() string {
	if pm.config != nil && pm.config.PKCS12.DefaultPassword != "" {
		return pm.config.PKCS12.DefaultPassword
	}
	return config.DefaultPKCS12Password
}

func (pm *PKCS12Manager) formatFriendlyName(domain string) string {
	base := config.DefaultPKCS12FriendlyName
	if pm.config != nil && pm.config.PKCS12.FriendlyName != "" {
		base = pm.config.PKCS12.FriendlyName
	}
	return fmt.Sprintf("%s - %s", base, domain)
}

// createWindowsCompatibilityFile 创建Windows兼容性文件
func (pm *PKCS12Manager) createWindowsCompatibilityFile(domain string, fileSafeDomain string, pfxData []byte, password string, friendlyName string) error {
	// 为Windows创建专门的PFX文件
	winPfxPath := filepath.Join(pm.config.CertDir, fmt.Sprintf("%s-client-windows.pfx", fileSafeDomain))

	// 读取证书数据重新编码
	certData, err := pm.loadCertificateData(domain)
	if err != nil {
		return err
	}

	// Windows可能需要不同的编码（这里简化处理）
	winPfxData, err := pkcs12.Encode(rand.Reader, certData.ClientKey, certData.ClientCert, certData.RootCerts, password)
	if err != nil {
		return err
	}

	return os.WriteFile(winPfxPath, winPfxData, 0600)
}

// generatePKCS12Info 生成PKCS12信息文件
func (pm *PKCS12Manager) generatePKCS12Info(domain string, p12Path string, friendlyName string, password string, clientCert *x509.Certificate, rootCerts []*x509.Certificate) error {
	if friendlyName == "" {
		friendlyName = pm.formatFriendlyName(domain)
	}
	info := &PKCS12Info{
		FriendlyName:     friendlyName,
		CreatedAt:        time.Now(),
		ExpiresAt:        clientCert.NotAfter,
		Subject:          clientCert.Subject.String(),
		Issuer:           clientCert.Issuer.String(),
		SerialNumber:     clientCert.SerialNumber.String(),
		KeyAlgorithm:     clientCert.PublicKeyAlgorithm.String(),
		KeySize:          pm.getKeySize(clientCert.PublicKey),
		CertificateCount: len(rootCerts) + 1,
	}

	// 获取文件大小
	if stat, err := os.Stat(p12Path); err == nil {
		info.FileSize = stat.Size()
	}

	// 生成信息文件内容
	infoContent := fmt.Sprintf(`# GenCert PKCS12 Certificate Information
# Domain: %s
# Generated: %s

## Certificate Information
- Friendly Name: %s
- Subject: %s
- Issuer: %s
- Serial Number: %s
- Valid From: %s
- Valid To: %s
- Key Algorithm: %s
- Key Size: %d bits
- Certificate Count: %d
- File Size: %d bytes

## Installation Instructions

### Windows
1. Double-click the .p12 file
2. Enter password: %s
3. Select "Current User" store
4. Place certificate in "Personal" store

### macOS
1. Double-click the .p12 file
2. Enter password: %s
3. Add to Keychain Access
4. Set trust settings for SSL/TLS

### Linux
1. Import into Firefox/Chrome certificate stores
2. Or use with OpenSSL commands
3. Configure applications to use the certificate

## Security Notes
- Keep the .p12 file secure as it contains your private key
- Use a strong password for the PKCS12 file
- Only share with trusted parties
- Back up your certificate regularly

## Support
For issues or questions, please check the documentation or create an issue.
`,
		domain,
		info.CreatedAt.Format("2025-09-16 15:04:05"),
		info.FriendlyName,
		info.Subject,
		info.Issuer,
		info.SerialNumber,
		clientCert.NotBefore.Format("2025-09-16 15:04:05"),
		clientCert.NotAfter.Format("2025-09-16 15:04:05"),
		info.KeyAlgorithm,
		info.KeySize,
		info.CertificateCount,
		info.FileSize,
		password,
		password,
	)

	fileSafeDomain := utils.SanitizeDomainForFilename(domain)
	infoPath := filepath.Join(pm.config.CertDir, fmt.Sprintf("%s-client-info.txt", fileSafeDomain))
	return os.WriteFile(infoPath, []byte(infoContent), 0644)
}

// getKeySize 获取密钥大小
func (pm *PKCS12Manager) getKeySize(publicKey crypto.PublicKey) int {
	if key, ok := publicKey.(*rsa.PublicKey); ok {
		return key.Size() * 8 // 转换为bits
	}
	return 0
}

// LoadPKCS12Bundle 加载PKCS12文件
func (pm *PKCS12Manager) LoadPKCS12Bundle(p12Path string, password string) (*PKCS12Info, *x509.Certificate, crypto.PrivateKey, []*x509.Certificate, error) {
	pm.logger.Info("加载PKCS12文件", logger.Str("path", p12Path))

	// 读取PKCS12文件
	pfxData, err := os.ReadFile(p12Path)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("读取PKCS12文件失败: %w", err)
	}

	// 解析PKCS12文件，并尽量保留完整链路
	privateKey, certificate, caCerts, err := pkcs12.DecodeChain(pfxData, password)
	if err != nil {
		// 回退到 Decode（仅返回证书本身）
		var decodeErr error
		privateKey, certificate, decodeErr = pkcs12.Decode(pfxData, password)
		if decodeErr != nil {
			// 更明确的错误分类
			if pm.isWrongPasswordError(err) || pm.isWrongPasswordError(decodeErr) {
				return nil, nil, nil, nil, fmt.Errorf("无法解锁 PKCS12，可能是密码错误: %w", err)
			}
			return nil, nil, nil, nil, fmt.Errorf("解析PKCS12失败，文件可能已损坏或不兼容: %w", err)
		}
		caCerts = []*x509.Certificate{}
	}

	// 生成PKCS12信息
	info := &PKCS12Info{
		CreatedAt:        certificate.NotBefore,
		ExpiresAt:        certificate.NotAfter,
		Subject:          certificate.Subject.String(),
		Issuer:           certificate.Issuer.String(),
		SerialNumber:     certificate.SerialNumber.String(),
		KeyAlgorithm:     certificate.PublicKeyAlgorithm.String(),
		KeySize:          pm.getKeySize(certificate.PublicKey),
		CertificateCount: len(caCerts) + 1,
		FileSize:         int64(len(pfxData)),
	}

	// 尝试获取友好名称
	if pfxInfo, err := pm.extractPKCS12Info(pfxData, password); err == nil && pfxInfo != nil {
		info.FriendlyName = pfxInfo.FriendlyName
	}
	if info.FriendlyName == "" {
		domainName := certificate.Subject.CommonName
		if strings.HasSuffix(domainName, "-client") {
			domainName = strings.TrimSuffix(domainName, "-client")
		}
		info.FriendlyName = pm.formatFriendlyName(domainName)
	}

	pm.logger.Info("PKCS12文件加载成功",
		logger.Str("friendly_name", info.FriendlyName),
		logger.Str("subject", info.Subject))

	return info, certificate, privateKey, caCerts, nil
}

// extractPKCS12Info 从PKCS12文件中提取信息
func (pm *PKCS12Manager) extractPKCS12Info(pfxData []byte, password string) (*PKCS12Info, error) {
	blocks, err := pkcs12.ToPEM(pfxData, password)
	if err != nil {
		return nil, fmt.Errorf("解析PKCS12属性失败: %w", err)
	}

	info := &PKCS12Info{}
	for _, block := range blocks {
		if name, ok := block.Headers["friendlyName"]; ok && name != "" {
			info.FriendlyName = name
			break
		}
	}

	return info, nil
}

// ValidatePKCS12File 验证PKCS12文件
func (pm *PKCS12Manager) ValidatePKCS12File(p12Path string, password string) error {
	pm.logger.Info("验证PKCS12文件", logger.Str("path", p12Path))

	// 检查文件是否存在
	if _, err := os.Stat(p12Path); os.IsNotExist(err) {
		return fmt.Errorf("PKCS12文件不存在: %w", err)
	}

	// 尝试加载文件
	_, _, _, _, err := pm.LoadPKCS12Bundle(p12Path, password)
	if err != nil {
		return fmt.Errorf("PKCS12文件验证失败: %w", err)
	}

	// 验证证书链
	// 这里可以添加更详细的证书链验证逻辑

	pm.logger.Info("PKCS12文件验证成功")
	return nil
}

// ExportPKCS12ToPEM 导出PKCS12为PEM格式
func (pm *PKCS12Manager) ExportPKCS12ToPEM(p12Path string, password string, outputPath string) error {
	pm.logger.Info("导出PKCS12为PEM格式",
		logger.Str("p12_path", p12Path),
		logger.Str("output_path", outputPath))

	// 加载PKCS12文件
	_, cert, privateKey, caCerts, err := pm.LoadPKCS12Bundle(p12Path, password)
	if err != nil {
		return err
	}

	// 创建PEM内容
	var pemContent strings.Builder

	// 写入私钥
	if keyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey); err == nil {
		pemBlock := &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: keyBytes,
		}
		pemContent.WriteString(string(pem.EncodeToMemory(pemBlock)))
	}

	// 写入证书
	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}
	pemContent.WriteString(string(pem.EncodeToMemory(pemBlock)))

	// 写入CA证书
	for _, caCert := range caCerts {
		pemBlock := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: caCert.Raw,
		}
		pemContent.WriteString(string(pem.EncodeToMemory(pemBlock)))
	}

	// 确保输出目录存在
	if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
		return fmt.Errorf("创建输出目录失败: %w", err)
	}

	// 保存PEM文件
	if err := os.WriteFile(outputPath, []byte(pemContent.String()), 0600); err != nil {
		return fmt.Errorf("保存PEM文件失败: %w", err)
	}

	pm.logger.Info("PKCS12导出PEM格式完成", logger.Str("output_path", outputPath))
	return nil
}

// GetPKCS12Info 获取PKCS12文件信息
func (pm *PKCS12Manager) GetPKCS12Info(p12Path string) (*PKCS12Info, error) {
	pm.logger.Info("获取PKCS12文件信息", logger.Str("path", p12Path))

	// 检查文件是否存在
	stat, err := os.Stat(p12Path)
	if err != nil {
		return nil, fmt.Errorf("获取PKCS12文件信息失败: %w", err)
	}

	// 读取文件内容
	pfxData, err := os.ReadFile(p12Path)
	if err != nil {
		return nil, fmt.Errorf("读取PKCS12文件失败: %w", err)
	}

	// 尝试解析PKCS12文件（使用默认密码尝试）
	info := &PKCS12Info{
		FileSize: stat.Size(),
	}

	// 尝试使用常见密码
	commonPasswords := []string{pm.defaultPassword(), "password", "", "123456"}
	for _, password := range commonPasswords {
		_, cert, err := pkcs12.Decode(pfxData, password)
		if err == nil && cert != nil {
			info.Subject = cert.Subject.String()
			info.Issuer = cert.Issuer.String()
			info.SerialNumber = cert.SerialNumber.String()
			info.KeyAlgorithm = cert.PublicKeyAlgorithm.String()
			info.KeySize = pm.getKeySize(cert.PublicKey)
			info.ExpiresAt = cert.NotAfter
			info.CertificateCount = 1
			break
		}
	}

	pm.logger.Info("PKCS12文件信息获取成功", logger.Str("subject", info.Subject))
	return info, nil
}

// ChangePKCS12Password 修改PKCS12文件密码
func (pm *PKCS12Manager) ChangePKCS12Password(p12Path string, oldPassword string, newPassword string) error {
	pm.logger.Info("修改PKCS12文件密码", logger.Str("path", p12Path))

	// 验证新密码
	if err := pm.validatePassword(newPassword); err != nil {
		return err
	}

	// 加载PKCS12文件
	_, cert, privateKey, caCerts, err := pm.LoadPKCS12Bundle(p12Path, oldPassword)
	if err != nil {
		if pm.isWrongPasswordError(err) {
			return fmt.Errorf("旧密码不正确: %w", err)
		}
		return err
	}

	// 创建新的PKCS12数据
	newPfxData, err := pkcs12.Encode(rand.Reader, privateKey, cert, caCerts, newPassword)
	if err != nil {
		return fmt.Errorf("创建新PKCS12文件失败: %w", err)
	}

	// 备份原文件并原地覆盖
	backupPath := p12Path + ".bak"
	if err := os.Rename(p12Path, backupPath); err != nil {
		return fmt.Errorf("备份原文件失败: %w", err)
	}
	if err := os.WriteFile(p12Path, newPfxData, 0600); err != nil {
		// 恢复备份
		_ = os.Rename(backupPath, p12Path)
		return fmt.Errorf("保存新PKCS12文件失败: %w", err)
	}
	_ = os.Remove(backupPath)

	pm.logger.Info("PKCS12文件密码修改成功")
	return nil
}

// ChangePKCS12PasswordTo 修改PKCS12文件密码并输出到新路径
func (pm *PKCS12Manager) ChangePKCS12PasswordTo(p12Path string, outPath string, oldPassword string, newPassword string) error {
	if outPath == "" || outPath == p12Path {
		return pm.ChangePKCS12Password(p12Path, oldPassword, newPassword)
	}

	pm.logger.Info("修改PKCS12文件密码(输出新文件)",
		logger.Str("src", p12Path),
		logger.Str("dst", outPath))

	if err := pm.validatePassword(newPassword); err != nil {
		return err
	}

	_, cert, privateKey, caCerts, err := pm.LoadPKCS12Bundle(p12Path, oldPassword)
	if err != nil {
		if pm.isWrongPasswordError(err) {
			return fmt.Errorf("旧密码不正确: %w", err)
		}
		return err
	}

	newPfxData, err := pkcs12.Encode(rand.Reader, privateKey, cert, caCerts, newPassword)
	if err != nil {
		return fmt.Errorf("创建新PKCS12文件失败: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
		return fmt.Errorf("创建输出目录失败: %w", err)
	}
	if err := os.WriteFile(outPath, newPfxData, 0600); err != nil {
		return fmt.Errorf("写入新PKCS12文件失败: %w", err)
	}

	pm.logger.Info("已生成新的PKCS12文件", logger.Str("dst", outPath))
	return nil
}

// isWrongPasswordError 判断是否为密码错误类错误
func (pm *PKCS12Manager) isWrongPasswordError(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "password") && (strings.Contains(s, "incorrect") || strings.Contains(s, "invalid") || strings.Contains(s, "wrong"))
}

// loadCertificate 加载证书
func (pm *PKCS12Manager) loadCertificate(path string) (*x509.Certificate, error) {
	certBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取证书文件失败: %w", err)
	}

	block, _ := pem.Decode(certBytes)
	if block == nil {
		return nil, fmt.Errorf("解析PEM证书失败")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("解析证书失败: %w", err)
	}

	return cert, nil
}

// loadPrivateKey 加载私钥
func (pm *PKCS12Manager) loadPrivateKey(path string) (*rsa.PrivateKey, error) {
	keyBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取私钥文件失败: %w", err)
	}

	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, fmt.Errorf("解析PEM私钥失败")
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("解析私钥失败: %w", err)
	}

	return key, nil
}

// ImportJavaKeyStore 导入到Java KeyStore
func (pm *PKCS12Manager) ImportJavaKeyStore(domain string, password string) error {
	pm.logger.Info("创建Java KeyStore", logger.Str("domain", domain))

	// 检查keytool命令是否可用
	if !pm.isKeytoolAvailable() {
		pm.logger.Warn("keytool命令不可用，跳过Java KeyStore创建")
		return fmt.Errorf("keytool命令不可用，请确保已安装JDK并配置了环境变量")
	}

	// 创建PKCS12文件
	fileSafeDomain := utils.SanitizeDomainForFilename(domain)
	p12Path := filepath.Join(pm.config.CertDir, fmt.Sprintf("%s-client.p12", fileSafeDomain))
	if _, err := os.Stat(p12Path); os.IsNotExist(err) {
		if err := pm.CreatePKCS12Bundle(domain, password); err != nil {
			return fmt.Errorf("创建PKCS12文件失败: %w", err)
		}
	}

	// 转换为JKS格式
	jksPath := filepath.Join(pm.config.CertDir, fmt.Sprintf("%s-client.jks", fileSafeDomain))
	if err := pm.convertToJKS(p12Path, jksPath, password); err != nil {
		return fmt.Errorf("转换为JKS格式失败: %w", err)
	}

	// 创建信任库
	trustStorePath := filepath.Join(pm.config.CertDir, fmt.Sprintf("%s-truststore.jks", fileSafeDomain))
	if err := pm.createTrustStore(trustStorePath, password); err != nil {
		return fmt.Errorf("创建信任库失败: %w", err)
	}

	pm.logger.Info("Java KeyStore创建完成")
	return nil
}

// isKeytoolAvailable 检查keytool是否可用
func (pm *PKCS12Manager) isKeytoolAvailable() bool {
	// 检查系统PATH中是否有keytool命令
	_, err := exec.LookPath("keytool")
	if err != nil {
		pm.logger.Debug("keytool命令未找到", logger.Err(err))
		return false
	}

	// 验证keytool是否可以执行
	cmd := exec.Command("keytool", "-help")
	if err := cmd.Run(); err != nil {
		pm.logger.Debug("keytool命令执行失败", logger.Err(err))
		return false
	}

	pm.logger.Debug("keytool命令可用")
	return true
}

// convertToJKS 转换为JKS格式
func (pm *PKCS12Manager) convertToJKS(p12Path, jksPath, password string) error {
	pm.logger.Info("转换PKCS12为JKS格式",
		logger.Str("p12_path", p12Path),
		logger.Str("jks_path", jksPath))

	// 检查PKCS12文件是否存在
	if _, err := os.Stat(p12Path); os.IsNotExist(err) {
		return fmt.Errorf("PKCS12文件不存在: %s", p12Path)
	}

	// 删除已存在的JKS文件
	if _, err := os.Stat(jksPath); err == nil {
		os.Remove(jksPath)
	}

	// 使用keytool转换PKCS12为JKS
	args := []string{
		"-importkeystore",
		"-srckeystore", p12Path,
		"-destkeystore", jksPath,
		"-srcstoretype", "PKCS12",
		"-deststoretype", "JKS",
		"-srcstorepass", password,
		"-deststorepass", password,
		"-noprompt",
	}

	cmd := exec.Command("keytool", args...)

	// 捕获输出
	output, err := cmd.CombinedOutput()
	if err != nil {
		pm.logger.Error("JKS转换失败",
			logger.Err(err),
			logger.Str("output", string(output)))
		return fmt.Errorf("JKS转换失败: %w, 输出: %s", err, string(output))
	}

	pm.logger.Info("JKS转换完成", logger.Str("jks_path", jksPath))
	return nil
}

// createTrustStore 创建信任库
func (pm *PKCS12Manager) createTrustStore(trustStorePath, password string) error {
	pm.logger.Info("创建Java信任库", logger.Str("truststore_path", trustStorePath))

	// 获取根CA证书路径
	rootCertPath := filepath.Join(pm.config.RootCADir, "rootCA.crt")

	// 检查根CA证书是否存在
	if _, err := os.Stat(rootCertPath); os.IsNotExist(err) {
		return fmt.Errorf("根CA证书不存在: %s", rootCertPath)
	}

	// 删除已存在的信任库文件
	if _, err := os.Stat(trustStorePath); err == nil {
		os.Remove(trustStorePath)
	}

	// 使用keytool创建信任库并导入根CA证书
	args := []string{
		"-importcert",
		"-alias", "rootca",
		"-keystore", trustStorePath,
		"-storepass", password,
		"-file", rootCertPath,
		"-trustcacerts",
		"-noprompt",
	}

	cmd := exec.Command("keytool", args...)

	// 捕获输出
	output, err := cmd.CombinedOutput()
	if err != nil {
		pm.logger.Error("信任库创建失败",
			logger.Err(err),
			logger.Str("output", string(output)))
		return fmt.Errorf("信任库创建失败: %w, 输出: %s", err, string(output))
	}

	pm.logger.Info("Java信任库创建完成", logger.Str("truststore_path", trustStorePath))
	return nil
}

// CreatePEMBundle 创建PEM格式证书包
func (pm *PKCS12Manager) CreatePEMBundle(domain string, password string) error {
	pm.logger.Info("创建PEM证书包", logger.Str("domain", domain))
	fileSafeDomain := utils.SanitizeDomainForFilename(domain)

	// 读取客户端证书和私钥
	clientCertPath := filepath.Join(pm.config.CertDir, fmt.Sprintf("%s-client.crt", fileSafeDomain))
	clientKeyPath := filepath.Join(pm.config.CertDir, fmt.Sprintf("%s-client.key", fileSafeDomain))
	rootCertPath := fmt.Sprintf("%s/rootCA.crt", pm.config.RootCADir)

	// 创建组合证书文件
	bundlePath := filepath.Join(pm.config.CertDir, fmt.Sprintf("%s-client-bundle.pem", fileSafeDomain))

	// 读取各文件内容
	clientCertBytes, err := os.ReadFile(clientCertPath)
	if err != nil {
		return fmt.Errorf("读取客户端证书失败: %w", err)
	}

	clientKeyBytes, err := os.ReadFile(clientKeyPath)
	if err != nil {
		return fmt.Errorf("读取客户端私钥失败: %w", err)
	}

	rootCertBytes, err := os.ReadFile(rootCertPath)
	if err != nil {
		return fmt.Errorf("读取根CA证书失败: %w", err)
	}

	// 创建bundle文件内容
	bundleContent := fmt.Sprintf(`# GenCert Client Certificate Bundle
# Domain: %s
# Password: %s
# Created: %s

# Private Key
%s
# Client Certificate
%s
# Root CA Certificate
%s
`, domain, password, time.Now().Format(time.RFC3339), string(clientKeyBytes), string(clientCertBytes), string(rootCertBytes))

	// 保存bundle文件
	if err := os.WriteFile(bundlePath, []byte(bundleContent), 0600); err != nil {
		return fmt.Errorf("保存证书包失败: %w", err)
	}

	pm.logger.Info("PEM证书包创建完成", logger.Str("path", bundlePath))
	return nil
}

// ValidateJavaKeyStore 验证Java KeyStore文件
func (pm *PKCS12Manager) ValidateJavaKeyStore(jksPath, password string) error {
	pm.logger.Info("验证Java KeyStore", logger.Str("jks_path", jksPath))

	// 检查文件是否存在
	if _, err := os.Stat(jksPath); os.IsNotExist(err) {
		return fmt.Errorf("Java KeyStore文件不存在: %s", jksPath)
	}

	// 使用keytool列出KeyStore内容
	args := []string{
		"-list",
		"-keystore", jksPath,
		"-storepass", password,
		"-v",
	}

	cmd := exec.Command("keytool", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		pm.logger.Error("Java KeyStore验证失败",
			logger.Err(err),
			logger.Str("output", string(output)))
		return fmt.Errorf("Java KeyStore验证失败: %w", err)
	}

	pm.logger.Info("Java KeyStore验证成功", logger.Str("jks_path", jksPath))
	return nil
}

// GetJavaKeyStoreInfo 获取Java KeyStore信息
func (pm *PKCS12Manager) GetJavaKeyStoreInfo(jksPath, password string) (map[string]string, error) {
	pm.logger.Info("获取Java KeyStore信息", logger.Str("jks_path", jksPath))

	// 检查文件是否存在
	if _, err := os.Stat(jksPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("Java KeyStore文件不存在: %s", jksPath)
	}

	// 使用keytool获取KeyStore信息
	args := []string{
		"-list",
		"-keystore", jksPath,
		"-storepass", password,
	}

	cmd := exec.Command("keytool", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		pm.logger.Error("获取Java KeyStore信息失败",
			logger.Err(err),
			logger.Str("output", string(output)))
		return nil, fmt.Errorf("获取Java KeyStore信息失败: %w", err)
	}

	// 解析输出获取基本信息
	info := make(map[string]string)
	outputStr := string(output)

	// 提取KeyStore类型
	if strings.Contains(outputStr, "JKS") {
		info["type"] = "JKS"
	} else if strings.Contains(outputStr, "PKCS12") {
		info["type"] = "PKCS12"
	}

	// 获取文件大小
	if stat, err := os.Stat(jksPath); err == nil {
		info["size"] = fmt.Sprintf("%d", stat.Size())
	}

	// 获取创建时间
	if stat, err := os.Stat(jksPath); err == nil {
		info["created"] = stat.ModTime().Format("2025-09-16 15:04:05")
	}

	pm.logger.Info("Java KeyStore信息获取成功", logger.Str("jks_path", jksPath))
	return info, nil
}

// CreateClientBundle 创建客户端证书包（包括PKCS12和PEM）
func (pm *PKCS12Manager) CreateClientBundle(domain string) error {
	password := pm.defaultPassword() // 默认密码

	// 创建PKCS12包
	if err := pm.CreatePKCS12Bundle(domain, password); err != nil {
		pm.logger.Warn("PKCS12包创建失败", logger.Err(err))
		// 如果PKCS12失败，创建PEM bundle作为备选
		if err := pm.CreatePEMBundle(domain, password); err != nil {
			return fmt.Errorf("创建PEM备选包也失败: %w", err)
		}
	}

	// 尝试创建Java KeyStore
	if err := pm.ImportJavaKeyStore(domain, password); err != nil {
		pm.logger.Warn("Java KeyStore创建失败", logger.Err(err))
	}

	return nil
}
