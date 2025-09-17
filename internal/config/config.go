package config

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/formzs/gencert/internal/errors"
	"github.com/spf13/viper"
)

const (
	DefaultPKCS12Password     = "HelloGenCert"
	DefaultPKCS12FriendlyName = "GenCert Client Certificate"
)

// Config 配置结构体
type Config struct {
	Debug        bool         `mapstructure:"debug"`
	RootCADir    string       `mapstructure:"root_ca_dir"`
	CertDir      string       `mapstructure:"cert_dir"`
	LogDir       string       `mapstructure:"log_dir"`
	ConfigFile   string       `mapstructure:"config_file"`
	Country      string       `mapstructure:"country"`
	State        string       `mapstructure:"state"`
	Locality     string       `mapstructure:"locality"`
	Organization string       `mapstructure:"organization"`
	OrgUnit      string       `mapstructure:"org_unit"`
	CommonName   string       `mapstructure:"common_name"`
	DefaultBits  int          `mapstructure:"default_bits"`
	DefaultDays  int          `mapstructure:"default_days"`
	PKCS12       PKCS12Config `mapstructure:"pkcs12"`
}

// PKCS12Config PKCS12 配置
type PKCS12Config struct {
	DefaultPassword string `mapstructure:"default_password"`
	FriendlyName    string `mapstructure:"friendly_name"`
}

// resolveDataDir 返回当前工作目录同级的 gencert-data 目录
func resolveDataDir(currentDir string) string {
	parentDir := filepath.Dir(currentDir)
	return filepath.Join(parentDir, "gencert-data")
}

// Init 初始化配置
func Init() (*Config, error) {
	return InitWithConfigFile("")
}

// InitWithConfigFile 使用指定配置文件初始化配置
func InitWithConfigFile(configFile string) (*Config, error) {
	// 设置默认值
	viper.SetDefault("debug", false)
	viper.SetDefault("country", "CN")
	viper.SetDefault("state", "Beijing")
	viper.SetDefault("locality", "ChaoYang")
	viper.SetDefault("organization", "CA")
	viper.SetDefault("org_unit", "Big")
	viper.SetDefault("common_name", "big.com")
	viper.SetDefault("default_bits", 2048)
	viper.SetDefault("default_days", 3650)
	viper.SetDefault("pkcs12.default_password", DefaultPKCS12Password)
	viper.SetDefault("pkcs12.friendly_name", DefaultPKCS12FriendlyName)

	// 获取当前目录
	currentDir, err := os.Getwd()
	if err != nil {
		return nil, errors.NewConfigError("获取当前目录失败", err)
	}
	dataDir := resolveDataDir(currentDir)

	// 设置默认目录路径
	viper.SetDefault("root_ca_dir", filepath.Join(dataDir, "ca"))
	viper.SetDefault("cert_dir", filepath.Join(dataDir, "certs"))
	viper.SetDefault("log_dir", filepath.Join(dataDir, "logs"))

	// 设置配置文件路径
	var configPath string
	if configFile != "" {
		configPath = configFile
	} else {
		configPath = filepath.Join(dataDir, "configs", "cert.yaml")
	}

	viper.Set("config_file", configPath)
	viper.SetConfigFile(configPath)

	// 读取配置文件
	if err := viper.ReadInConfig(); err != nil {
		// 检查文件是否存在
		if _, err := os.Stat(configPath); os.IsNotExist(err) {
			// 配置文件不存在，创建默认配置
			if err := createDefaultConfig(configPath); err != nil {
				return nil, errors.Wrap(err, "创建默认配置失败")
			}
			// 重新读取创建的配置文件
			if err := viper.ReadInConfig(); err != nil {
				return nil, errors.Wrap(err, "读取默认配置文件失败")
			}
		} else {
			return nil, errors.Wrap(err, "读取配置文件失败")
		}
	}

	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, errors.NewConfigError("解析配置失败", err)
	}

	if cfg.PKCS12.DefaultPassword == "" {
		cfg.PKCS12.DefaultPassword = DefaultPKCS12Password
	}
	if cfg.PKCS12.FriendlyName == "" {
		cfg.PKCS12.FriendlyName = DefaultPKCS12FriendlyName
	}

	// 转换相对路径为绝对路径
	cfg = cfg.normalizePaths()

	return &cfg, nil
}

// InitConfigFile 初始化配置文件（交互式）
func InitConfigFile(configFile string, interactive bool) error {
	var configPath string
	var cfg Config

	if configFile != "" {
		configPath = configFile
	} else {
		currentDir, err := os.Getwd()
		if err != nil {
			return errors.NewConfigError("获取当前目录失败", err)
		}
		dataDir := resolveDataDir(currentDir)
		configPath = filepath.Join(dataDir, "configs", "cert.yaml")
	}

	// 检查配置文件是否已存在
	if _, err := os.Stat(configPath); err == nil {
		fmt.Printf("配置文件 %s 已存在，是否覆盖？(y/N): ", configPath)
		reader := bufio.NewReader(os.Stdin)
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		if input != "y" && input != "Y" {
			fmt.Println("配置文件创建已取消")
			return nil
		}
	}

	if interactive {
		// 交互式配置
		cfg = interactiveConfig()
	} else {
		// 使用默认配置
		cfg = getDefaultConfig()
	}

	// 创建配置文件
	return createConfigFile(configPath, cfg)
}

// interactiveConfig 交互式配置
func interactiveConfig() Config {
	reader := bufio.NewReader(os.Stdin)
	cfg := getDefaultConfig()

	fmt.Println("=== GenCert 配置文件初始化 ===")
	fmt.Println("按Enter使用默认值")

	fmt.Printf("国家代码 (默认: %s): ", cfg.Country)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)
	if input != "" {
		cfg.Country = input
	}

	fmt.Printf("省份/州 (默认: %s): ", cfg.State)
	input, _ = reader.ReadString('\n')
	input = strings.TrimSpace(input)
	if input != "" {
		cfg.State = input
	}

	fmt.Printf("城市 (默认: %s): ", cfg.Locality)
	input, _ = reader.ReadString('\n')
	input = strings.TrimSpace(input)
	if input != "" {
		cfg.Locality = input
	}

	fmt.Printf("组织名称 (默认: %s): ", cfg.Organization)
	input, _ = reader.ReadString('\n')
	input = strings.TrimSpace(input)
	if input != "" {
		cfg.Organization = input
	}

	fmt.Printf("组织单位 (默认: %s): ", cfg.OrgUnit)
	input, _ = reader.ReadString('\n')
	input = strings.TrimSpace(input)
	if input != "" {
		cfg.OrgUnit = input
	}

	fmt.Printf("通用名称 (默认: %s): ", cfg.CommonName)
	input, _ = reader.ReadString('\n')
	input = strings.TrimSpace(input)
	if input != "" {
		cfg.CommonName = input
	}

	fmt.Printf("密钥长度 (默认: %d): ", cfg.DefaultBits)
	input, _ = reader.ReadString('\n')
	input = strings.TrimSpace(input)
	if input != "" {
		fmt.Sscanf(input, "%d", &cfg.DefaultBits)
	}

	fmt.Printf("证书有效期 (天) (默认: %d): ", cfg.DefaultDays)
	input, _ = reader.ReadString('\n')
	input = strings.TrimSpace(input)
	if input != "" {
		fmt.Sscanf(input, "%d", &cfg.DefaultDays)
	}

	return cfg
}

// getDefaultConfig 获取默认配置
func getDefaultConfig() Config {
	return Config{
		Debug:        false,
		RootCADir:    filepath.ToSlash(filepath.Join("..", "gencert-data", "ca")),
		CertDir:      filepath.ToSlash(filepath.Join("..", "gencert-data", "certs")),
		LogDir:       filepath.ToSlash(filepath.Join("..", "gencert-data", "logs")),
		ConfigFile:   filepath.ToSlash(filepath.Join("..", "gencert-data", "configs", "cert.yaml")),
		Country:      "CN",
		State:        "Beijing",
		Locality:     "ChaoYang",
		Organization: "CA",
		OrgUnit:      "Development",
		CommonName:   "Development CA",
		DefaultBits:  2048,
		DefaultDays:  3650,
		PKCS12: PKCS12Config{
			DefaultPassword: DefaultPKCS12Password,
			FriendlyName:    DefaultPKCS12FriendlyName,
		},
	}
}

// NewDefaultConfig 返回基于当前工作目录的默认配置（不触发文件写入）
func NewDefaultConfig() *Config {
	currentDir, err := os.Getwd()
	if err != nil {
		cfg := getDefaultConfig()
		normalized := cfg.normalizePaths()
		return &normalized
	}

	dataDir := resolveDataDir(currentDir)
	cfg := getDefaultConfig()
	cfg.RootCADir = filepath.Join(dataDir, "ca")
	cfg.CertDir = filepath.Join(dataDir, "certs")
	cfg.LogDir = filepath.Join(dataDir, "logs")
	cfg.ConfigFile = filepath.Join(dataDir, "configs", "cert.yaml")

	normalized := cfg.normalizePaths()
	return &normalized
}

// createConfigFile 创建配置文件
func createConfigFile(path string, cfg Config) error {
	// 确保配置文件目录存在
	configDir := filepath.Dir(path)
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return errors.NewFileSystemError("创建配置目录失败", err)
	}

	// 生成配置内容
	configContent := fmt.Sprintf(`# GenCert 配置文件
# 生成时间: %s

# 调试模式
debug: %v

# 证书主题信息
country: %s
state: %s
locality: %s
organization: %s
org_unit: %s
common_name: %s

# 证书参数
default_bits: %d
default_days: %d

# 目录配置
root_ca_dir: %s
cert_dir: %s
log_dir: %s

# PKCS12配置
pkcs12:
  default_password: "%s"
  friendly_name: "%s"
`,
		time.Now().Format("2025-09-16 15:04:05"),
		cfg.Debug,
		cfg.Country, cfg.State, cfg.Locality, cfg.Organization, cfg.OrgUnit, cfg.CommonName,
		cfg.DefaultBits, cfg.DefaultDays,
		cfg.RootCADir, cfg.CertDir, cfg.LogDir,
		cfg.PKCS12.DefaultPassword, cfg.PKCS12.FriendlyName,
	)

	if err := os.WriteFile(path, []byte(configContent), 0644); err != nil {
		return errors.NewFileSystemError("写入配置文件失败", err)
	}

	fmt.Printf("配置文件已创建: %s\n", path)
	return nil
}

// createDefaultConfig 创建默认配置文件
func createDefaultConfig(path string) error {
	// 确保配置文件目录存在
	configDir := filepath.Dir(path)
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return errors.NewFileSystemError("创建配置目录失败", err)
	}

	// 默认配置内容
	defaultCfg := getDefaultConfig()
	defaultConfig := fmt.Sprintf(`# GenCert 配置文件
debug: %t

# 目录配置
root_ca_dir: %s
cert_dir: %s
log_dir: %s

# 证书主题信息
country: %s
state: %s
locality: %s
organization: %s
org_unit: %s
common_name: %s

# 证书参数
default_bits: %d
default_days: %d

# PKCS12配置
pkcs12:
  default_password: "%s"
  friendly_name: "%s"
`,
		defaultCfg.Debug,
		defaultCfg.RootCADir,
		defaultCfg.CertDir,
		defaultCfg.LogDir,
		defaultCfg.Country,
		defaultCfg.State,
		defaultCfg.Locality,
		defaultCfg.Organization,
		defaultCfg.OrgUnit,
		defaultCfg.CommonName,
		defaultCfg.DefaultBits,
		defaultCfg.DefaultDays,
		defaultCfg.PKCS12.DefaultPassword,
		defaultCfg.PKCS12.FriendlyName,
	)

	if err := os.WriteFile(path, []byte(defaultConfig), 0644); err != nil {
		return errors.NewFileSystemError("写入默认配置文件失败", err)
	}
	return nil
}

// GetSubject 获取证书主题信息
func (c *Config) GetSubject() map[string]string {
	return map[string]string{
		"country":            c.Country,
		"state":              c.State,
		"locality":           c.Locality,
		"organization":       c.Organization,
		"organizationalUnit": c.OrgUnit,
		"commonName":         c.CommonName,
	}
}

// GetRootCASubject 获取根CA主题信息
func (c *Config) GetRootCASubject() map[string]string {
	return map[string]string{
		"country":            c.Country,
		"state":              c.State,
		"locality":           c.Locality,
		"organization":       c.Organization,
		"organizationalUnit": "Root CA",
		"commonName":         fmt.Sprintf("%s Root CA", c.Organization),
	}
}

// normalizePaths 规范化路径，将相对路径转换为绝对路径
func (c *Config) normalizePaths() Config {
	// 获取当前工作目录
	currentDir, _ := os.Getwd()

	// 规范化各个路径
	if !filepath.IsAbs(c.RootCADir) {
		c.RootCADir = filepath.Join(currentDir, c.RootCADir)
	}
	if !filepath.IsAbs(c.CertDir) {
		c.CertDir = filepath.Join(currentDir, c.CertDir)
	}
	if !filepath.IsAbs(c.LogDir) {
		c.LogDir = filepath.Join(currentDir, c.LogDir)
	}
	if !filepath.IsAbs(c.ConfigFile) {
		c.ConfigFile = filepath.Join(currentDir, c.ConfigFile)
	}

	return *c
}
