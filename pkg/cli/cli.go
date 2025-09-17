package cli

import (
	"bufio"
	stdx509 "crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/formzs/gencert/internal/config"
	"github.com/formzs/gencert/internal/crypto"
	"github.com/formzs/gencert/internal/logger"
	"github.com/formzs/gencert/internal/utils"
	"github.com/formzs/gencert/internal/version"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// Execute 执行CLI命令
func Execute(cfg *config.Config, log logger.Logger) error {
	rootCmd := NewRootCommand(cfg, log)
	return rootCmd.Execute()
}

// NewRootCommand 创建根命令
func NewRootCommand(cfg *config.Config, log logger.Logger) *cobra.Command {
	var debug bool
	var version bool
	var configFile string
	var sanValues []string

	cmd := &cobra.Command{
		Use:   "GenCert [command] [flags]",
		Short: "GenCert - 证书生成",
		Long: `GenCert 是一个简单易用的证书管理工具，用于生成根证书、服务器证书和客户端证书。
适用于开发和测试环境，支持HTTPS和双向SSL/TLS验证。

示例:
  gencert init              # 初始化配置文件
  gencert init -i           # 交互式初始化配置文件
  gencert example.com       # 生成证书
  gencert -c my.yaml example.com  # 使用指定配置文件生成证书
  gencert -d example.com    # 启用调试模式`,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			// 处理版本命令（在参数验证之前）
			if version {
				printVersion()
				os.Exit(0)
			}

			// 更新配置中的调试模式
			if debug {
				cfg.Debug = true
				// 重新初始化日志系统以启用调试模式
				log = logger.NewWithFile(cfg.Debug, cfg.LogDir)
			}

			// 如果指定了配置文件，重新初始化配置
			if configFile != "" && cmd.Name() != "init" {
				newCfg, err := config.InitWithConfigFile(configFile)
				if err != nil {
					fmt.Printf("加载配置文件失败: %v\n", err)
					os.Exit(1)
				}
				*cfg = *newCfg
			}
		},
	}

	// 添加全局标志
	cmd.PersistentFlags().BoolVarP(&debug, "debug", "d", false, "启用调试模式")
	cmd.PersistentFlags().BoolVarP(&version, "version", "v", false, "显示版本信息")
	cmd.PersistentFlags().StringVarP(&configFile, "config", "c", "", "指定配置文件路径")
	cmd.PersistentFlags().StringSliceVar(&sanValues, "san", nil, "为证书添加额外的 SAN 域名，可重复指定或以逗号分隔")
	cmd.PersistentFlags().BoolP("help", "h", false, "显示帮助信息")

	// 添加子命令
	cmd.AddCommand(newInitCommand())
	cmd.AddCommand(newGenerateCommand(cfg, log))
	cmd.AddCommand(newPKCS12Command(cfg, log))

	// 设置默认运行命令为生成证书
	cmd.Run = func(cmd *cobra.Command, args []string) {
		// 如果没有子命令，默认执行生成证书
		if len(args) < 1 {
			fmt.Println("错误：需要指定域名或使用 init 命令初始化配置文件")
			cmd.Help()
			os.Exit(1)
		}

		if err := runGenerateCertificates(cfg, log, cmd, args); err != nil {
			log.Error("生成证书失败", logger.Err(err))
			os.Exit(1)
		}
	}

	return cmd
}

// newInitCommand 创建初始化命令
func newInitCommand() *cobra.Command {
	var interactive bool
	var configFile string

	cmd := &cobra.Command{
		Use:   "init",
		Short: "初始化配置文件",
		Long:  "初始化GenCert配置文件，支持交互式配置和自定义配置文件路径",
		Run: func(cmd *cobra.Command, args []string) {
			if err := config.InitConfigFile(configFile, interactive); err != nil {
				fmt.Printf("初始化配置文件失败: %v\n", err)
				os.Exit(1)
			}
		},
	}

	cmd.Flags().BoolVarP(&interactive, "interactive", "i", false, "启用交互式配置")
	cmd.Flags().StringVarP(&configFile, "config", "c", "", "指定配置文件路径")

	return cmd
}

// newGenerateCommand 创建生成证书命令
func newGenerateCommand(cfg *config.Config, log logger.Logger) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "generate [domains...]",
		Short: "生成SSL证书",
		Long: `生成根CA证书、服务器证书和客户端证书。
支持为多个域名批量生成证书，并可通过 --san 指定额外的 SAN 域名。`,
		Args: cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if err := runGenerateCertificates(cfg, log, cmd, args); err != nil {
				log.Error("生成证书失败", logger.Err(err))
				os.Exit(1)
			}
		},
	}

	return cmd
}

// newPKCS12Command 创建 PKCS12 管理命令
func newPKCS12Command(cfg *config.Config, log logger.Logger) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pkcs12",
		Short: "管理 PKCS12 证书包",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Help()
		},
	}

	cmd.AddCommand(newPKCS12ChangePasswordCommand(cfg, log))
	cmd.AddCommand(newPKCS12InfoCommand(cfg, log))

	return cmd
}

// newPKCS12ChangePasswordCommand 创建修改 PKCS12 密码命令
func newPKCS12ChangePasswordCommand(cfg *config.Config, log logger.Logger) *cobra.Command {
	var inputPath string
	var oldPassword string
	var newPassword string
	var outputPath string
	var noPrompt bool

	cmd := &cobra.Command{
		Use:   "change-password",
		Short: "修改 PKCS12 证书包密码",
		RunE: func(cmd *cobra.Command, args []string) error {
			if inputPath == "" {
				return fmt.Errorf("需要指定 --input")
			}
			// 读取旧密码：优先参数，其次环境变量，最后交互/默认
			if oldPassword == "" {
				if v := os.Getenv("GENCERT_OLD_PASSWORD"); v != "" {
					oldPassword = v
				}
			}
			// 若仍为空且允许交互，则提示输入（回车使用默认）
			if oldPassword == "" && !noPrompt {
				if pwd, err := readPassword("请输入旧密码(回车使用默认): "); err == nil {
					oldPassword = pwd
				} else {
					return err
				}
			}
			if oldPassword == "" {
				oldPassword = cfg.PKCS12.DefaultPassword
			}

			// 读取新密码：优先参数，其次环境变量，最后交互输入（带确认）
			if newPassword == "" {
				if v := os.Getenv("GENCERT_NEW_PASSWORD"); v != "" {
					newPassword = v
				}
			}
			if newPassword == "" && !noPrompt {
				pwd, err := readPassword("请输入新密码: ")
				if err != nil {
					return err
				}
				confirm, err := readPassword("请再次输入新密码: ")
				if err != nil {
					return err
				}
				if pwd != confirm {
					return fmt.Errorf("两次输入的新密码不一致")
				}
				newPassword = pwd
			}
			if newPassword == "" {
				return fmt.Errorf("需要指定 --new 或通过环境变量/交互式输入提供新密码")
			}

			if oldPassword == "" {
				oldPassword = cfg.PKCS12.DefaultPassword
			}

			pm := crypto.NewPKCS12Manager(cfg, log)
			if outputPath != "" {
				if err := pm.ChangePKCS12PasswordTo(inputPath, outputPath, oldPassword, newPassword); err != nil {
					return fmt.Errorf("修改密码失败: %w", err)
				}
				cmd.Printf("已生成新 PKCS12 文件: %s\n", outputPath)
			} else {
				if err := pm.ChangePKCS12Password(inputPath, oldPassword, newPassword); err != nil {
					return fmt.Errorf("修改密码失败: %w", err)
				}
				// 使用 cobra 的输出，以便在测试中可捕获
				cmd.Printf("已更新 PKCS12 密码: %s\n", inputPath)
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&inputPath, "input", "i", "", "PKCS12 文件路径")
	cmd.Flags().StringVar(&oldPassword, "old", "", "旧密码（默认读取配置）")
	cmd.Flags().StringVar(&newPassword, "new", "", "新密码")
	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "输出文件路径（不指定则原地覆盖）")
	cmd.Flags().BoolVar(&noPrompt, "no-prompt", false, "禁止交互式输入（CI环境使用）")

	return cmd
}

// newPKCS12InfoCommand 创建 PKCS12 信息查看命令
func newPKCS12InfoCommand(cfg *config.Config, log logger.Logger) *cobra.Command {
	var inputPath string
	var password string

	cmd := &cobra.Command{
		Use:   "info",
		Short: "查看 PKCS12 证书包信息",
		RunE: func(cmd *cobra.Command, args []string) error {
			if inputPath == "" {
				return fmt.Errorf("需要指定 --input")
			}

			pwd := password
			if pwd == "" {
				if v := os.Getenv("GENCERT_P12_PASSWORD"); v != "" {
					pwd = v
				}
			}
			if pwd == "" {
				if p, err := readPassword("请输入 PKCS12 密码(回车使用默认): "); err == nil {
					pwd = p
				} else {
					return err
				}
			}
			if pwd == "" {
				pwd = cfg.PKCS12.DefaultPassword
			}

			pm := crypto.NewPKCS12Manager(cfg, log)
			info, cert, _, chain, err := pm.LoadPKCS12Bundle(inputPath, pwd)
			if err != nil {
				fallback, fallbackErr := pm.GetPKCS12Info(inputPath)
				if fallbackErr == nil {
					cmd.Printf("无法使用指定密码解锁，展示有限信息：\n")
					printPKCS12Info(cmd, fallback, nil)
				}
				return fmt.Errorf("加载 PKCS12 失败: %w", err)
			}

			cmd.Printf("PKCS12 文件信息 (%s)\n", inputPath)
			printPKCS12Info(cmd, info, chain)

			if cert != nil {
				cmd.Printf("证书指纹 (SHA1): %X\n", cert.SerialNumber)
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&inputPath, "input", "i", "", "PKCS12 文件路径")
	cmd.Flags().StringVar(&password, "password", "", "包密码（默认读取配置）")

	return cmd
}

// printPKCS12Info 打印 PKCS12 信息（输出到 cobra 输出流）
func printPKCS12Info(cmd *cobra.Command, info *crypto.PKCS12Info, chain []*stdx509.Certificate) {
	if info == nil {
		cmd.Println("(无可用信息)")
		return
	}

	formatTime := func(t time.Time) string {
		if t.IsZero() {
			return "-"
		}
		return t.Format("2025-09-16 15:04:05")
	}

	cmd.Printf("友好名称: %s\n", info.FriendlyName)
	cmd.Printf("主题: %s\n", info.Subject)
	cmd.Printf("颁发者: %s\n", info.Issuer)
	cmd.Printf("序列号: %s\n", info.SerialNumber)
	cmd.Printf("公钥算法: %s (%d bits)\n", info.KeyAlgorithm, info.KeySize)
	cmd.Printf("签发时间: %s\n", formatTime(info.CreatedAt))
	cmd.Printf("到期时间: %s\n", formatTime(info.ExpiresAt))
	cmd.Printf("证书数量: %d\n", info.CertificateCount)
	cmd.Printf("文件大小: %d bytes\n", info.FileSize)

	if chain != nil && len(chain) > 0 {
		cmd.Println("证书链:")
		for idx, ca := range chain {
			cmd.Printf("  [%d] %s\n", idx+1, ca.Subject.String())
		}
	}
}

// readPassword 读取隐藏输入的密码；非 TTY 环境回退为明文读取一行
func readPassword(prompt string) (string, error) {
	// 优先向标准输出提示，便于交互
	fmt.Fprint(os.Stdout, prompt)
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		b, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stdout)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(b)), nil
	}
	// 非交互环境：读取一行
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil && err.Error() != "EOF" {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

// runGenerateCertificates 运行证书生成
func runGenerateCertificates(cfg *config.Config, log logger.Logger, cmd *cobra.Command, domains []string) error {
	sanValues, err := cmd.Flags().GetStringSlice("san")
	if err != nil {
		return fmt.Errorf("读取 SAN 参数失败: %w", err)
	}

	trimmedSAN := make([]string, 0, len(sanValues))
	for _, v := range sanValues {
		for _, item := range strings.Split(v, ",") {
			s := strings.TrimSpace(item)
			if s != "" {
				trimmedSAN = append(trimmedSAN, s)
			}
		}
	}

	certManager := crypto.NewCertificateManager(cfg, log)
	if err := certManager.GenerateRootCA(); err != nil {
		return fmt.Errorf("生成根CA失败: %w", err)
	}

	for _, rawDomain := range domains {
		domain := strings.TrimSpace(rawDomain)
		if domain == "" {
			continue
		}

		log.Info("开始生成证书", logger.Str("domain", domain), logger.Str("san", strings.Join(trimmedSAN, ",")))

		if err := certManager.GenerateCertificates(domain, trimmedSAN); err != nil {
			return fmt.Errorf("生成域名 %s 证书失败: %w", domain, err)
		}

		log.Info("证书生成完成", logger.Str("domain", domain))
		printGeneratedFiles(cfg, domain)
	}

	return nil
}

// printGeneratedFiles 打印生成的文件信息
func printGeneratedFiles(cfg *config.Config, domain string) {
	password := cfg.PKCS12.DefaultPassword
	if password == "" {
		password = config.DefaultPKCS12Password
	}

	safeDomain := utils.SanitizeDomainForFilename(domain)
	rootCertPath := filepath.Join(cfg.RootCADir, "rootCA.crt")
	serverCertPath := filepath.Join(cfg.CertDir, fmt.Sprintf("%s.crt", safeDomain))
	serverKeyPath := filepath.Join(cfg.CertDir, fmt.Sprintf("%s.key", safeDomain))
	serverChainPath := filepath.Join(cfg.CertDir, fmt.Sprintf("%s-chain.pem", safeDomain))
	clientCertPath := filepath.Join(cfg.CertDir, fmt.Sprintf("%s-client.crt", safeDomain))
	clientKeyPath := filepath.Join(cfg.CertDir, fmt.Sprintf("%s-client.key", safeDomain))
	clientChainPath := filepath.Join(cfg.CertDir, fmt.Sprintf("%s-client-chain.pem", safeDomain))
	clientP12Path := filepath.Join(cfg.CertDir, fmt.Sprintf("%s-client.p12", safeDomain))

	fmt.Println("\n生成的SSL文件:")
	fmt.Println("根证书文件:")
	fmt.Printf("  - 根证书: %s\n", rootCertPath)

	fmt.Println("\n服务器端配置文件:")
	fmt.Printf("  - 服务器证书: %s\n", serverCertPath)
	fmt.Printf("  - 服务器私钥: %s\n", serverKeyPath)
	fmt.Printf("  - 服务器证书链: %s\n", serverChainPath)

	fmt.Println("\n客户端配置文件:")
	fmt.Printf("  - 客户端证书: %s\n", clientCertPath)
	fmt.Printf("  - 客户端私钥: %s\n", clientKeyPath)
	fmt.Printf("  - 客户端证书链: %s\n", clientChainPath)
	fmt.Printf("  - 客户端PKCS12格式: %s (密码: %s)\n", clientP12Path, password)

	fmt.Println("\nPostgreSQL JDBC连接示例:")
	fmt.Printf("jdbc:postgresql://%s:5432/dbname?ssl=true&sslmode=verify-full&sslrootcert=%s&sslcert=%s&sslkey=%s\n",
		domain, rootCertPath, clientCertPath, clientKeyPath)

	fmt.Println("\n或使用PKCS12格式 (推荐):")
	fmt.Printf("jdbc:postgresql://%s:5432/dbname?ssl=true&sslmode=verify-full&sslrootcert=%s&sslcert=%s&sslpassword=%s\n",
		domain, rootCertPath, clientP12Path, password)
}

// printVersion 打印版本信息
func printVersion() {
	version.PrintVersion()
}
