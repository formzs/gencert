package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/formzs/gencert/internal/config"
	"github.com/formzs/gencert/internal/logger"
	"github.com/formzs/gencert/internal/version"
	"github.com/formzs/gencert/pkg/cli"
)

func main() {
	args := os.Args[1:]
	firstArg, _ := firstNonFlagArg(args)
	primary := strings.ToLower(firstArg)

	if primary != "" && !isKnownCommand(primary) {
		os.Args = append([]string{os.Args[0], "generate"}, os.Args[1:]...)
	}

	isInit := primary == "init"

	var (
		cfg *config.Config
		err error
		log logger.Logger
	)

	if isInit {
		cfg = config.NewDefaultConfig()
		log = logger.New(cfg.Debug)
	} else {
		cfg, err = config.Init()
		if err != nil {
			fmt.Printf("配置初始化失败: %v\n", err)
			os.Exit(1)
		}

		log = logger.NewWithFile(cfg.Debug, cfg.LogDir)
	}

	log.Info("GenCert 启动",
		logger.Str("version", version.Version),
		logger.Str("build_time", version.BuildTime),
		logger.Str("commit_hash", version.CommitHash))

	if !isInit {
		if err := ensureDirectories(cfg); err != nil {
			log.Error("创建目录失败", logger.Err(err))
			os.Exit(1)
		}
	}

	if err := cli.Execute(cfg, log); err != nil {
		log.Error("执行失败", logger.Err(err))
		os.Exit(1)
	}
}

func firstNonFlagArg(args []string) (string, int) {
	skipNext := false
	for idx, arg := range args {
		if skipNext {
			skipNext = false
			continue
		}

		switch {
		case arg == "--":
			if idx+1 < len(args) {
				return args[idx+1], idx + 1
			}
			return "", -1
		case strings.HasPrefix(arg, "--"):
			if eq := strings.Index(arg, "="); eq != -1 {
				continue
			}
			switch strings.TrimPrefix(arg, "--") {
			case "config", "san":
				skipNext = true
			}
			continue
		case strings.HasPrefix(arg, "-") && len(arg) > 1:
			if strings.Contains(arg, "=") {
				continue
			}
			flags := arg[1:]
			if flags == "c" {
				skipNext = true
			}
			continue
		default:
			return arg, idx
		}
	}

	return "", -1
}

func isKnownCommand(cmd string) bool {
	switch cmd {
	case "", "init", "generate", "help", "completion", "version":
		return true
	default:
		return false
	}
}

// ensureDirectories 确保所有必要的目录都存在
func ensureDirectories(cfg *config.Config) error {
	dirs := []string{
		cfg.RootCADir,
		cfg.CertDir,
		cfg.LogDir,
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("创建目录 %s 失败: %w", dir, err)
		}
	}

	return nil
}
