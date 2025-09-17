package logger

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/rs/zerolog"
)

// Logger 日志接口
type Logger interface {
	Debug(msg string, fields ...Field)
	Info(msg string, fields ...Field)
	Warn(msg string, fields ...Field)
	Error(msg string, fields ...Field)
	Fatal(msg string, fields ...Field)
	Message(msg string, fields ...Field)
	With(fields ...Field) Logger
}

// Field 日志字段
type Field struct {
	Key   string
	Value interface{}
}

// ZerologLogger 基于zerolog的日志实现
type ZerologLogger struct {
	logger zerolog.Logger
}

// New 创建新的日志实例
func New(debug bool) Logger {
	// 设置日志级别
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	if debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}

	// 创建控制台输出
	consoleWriter := zerolog.ConsoleWriter{
		Out:        os.Stdout,
		TimeFormat: "2025-09-16 15:04:05",
		NoColor:    false,
	}

	// 创建多输出
	multi := zerolog.MultiLevelWriter(consoleWriter)

	// 创建日志实例
	logger := zerolog.New(multi).With().Timestamp().Logger()

	return &ZerologLogger{logger: logger}
}

// NewWithFile 创建带文件输出的日志实例
func NewWithFile(debug bool, logDir string) Logger {
	// 设置日志级别
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	if debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}

	// 确保日志目录存在
	if err := os.MkdirAll(logDir, 0755); err != nil {
		panic(fmt.Sprintf("创建日志目录失败: %v", err))
	}

	// 日志文件路径
	logFile := filepath.Join(logDir, fmt.Sprintf("gencert_%s.log", time.Now().Format("20060102_150405")))
	errorLogFile := filepath.Join(logDir, "error.log")

	// 创建日志文件输出
	fileWriter, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		panic(fmt.Sprintf("创建日志文件失败: %v", err))
	}

	errorFileWriter, err := os.OpenFile(errorLogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		panic(fmt.Sprintf("创建错误日志文件失败: %v", err))
	}

	// 创建控制台输出
	consoleWriter := zerolog.ConsoleWriter{
		Out:        os.Stdout,
		TimeFormat: "2025-09-16 15:04:05",
		NoColor:    false,
	}

	// 创建多输出
	multi := zerolog.MultiLevelWriter(
		consoleWriter,
		fileWriter,
	)

	// 错误级别额外输出到错误文件
	errorMulti := zerolog.MultiLevelWriter(
		errorFileWriter,
	)

	// 创建日志实例
	logger := zerolog.New(multi).With().Timestamp().Logger()
	errorLogger := zerolog.New(errorMulti).With().Timestamp().Logger()

	// 组合日志器
	combinedLogger := logger.Hook(errorHook{errorLogger: errorLogger})

	return &ZerologLogger{logger: combinedLogger}
}

// errorHook 错误日志钩子
type errorHook struct {
	errorLogger zerolog.Logger
}

func (h errorHook) Run(e *zerolog.Event, level zerolog.Level, msg string) {
	if level >= zerolog.ErrorLevel {
		// 复制事件到错误日志
		h.errorLogger.WithLevel(level).Msg(msg)
	}
}

// Debug 调试日志
func (l *ZerologLogger) Debug(msg string, fields ...Field) {
	event := l.logger.Debug()
	for _, field := range fields {
		event = event.Interface(field.Key, field.Value)
	}
	event.Msg(msg)
}

// Info 信息日志
func (l *ZerologLogger) Info(msg string, fields ...Field) {
	event := l.logger.Info()
	for _, field := range fields {
		event = event.Interface(field.Key, field.Value)
	}
	event.Msg(msg)
}

// Warn 警告日志
func (l *ZerologLogger) Warn(msg string, fields ...Field) {
	event := l.logger.Warn()
	for _, field := range fields {
		event = event.Interface(field.Key, field.Value)
	}
	event.Msg(msg)
}

// Error 错误日志
func (l *ZerologLogger) Error(msg string, fields ...Field) {
	event := l.logger.Error()
	for _, field := range fields {
		event = event.Interface(field.Key, field.Value)
	}
	event.Msg(msg)
}

// Fatal 致命错误日志
func (l *ZerologLogger) Fatal(msg string, fields ...Field) {
	event := l.logger.Fatal()
	for _, field := range fields {
		event = event.Interface(field.Key, field.Value)
	}
	event.Msg(msg)
}

// Message 消息日志（始终显示）
func (l *ZerologLogger) Message(msg string, fields ...Field) {
	event := l.logger.Info()
	for _, field := range fields {
		event = event.Interface(field.Key, field.Value)
	}
	event.Msg(msg)
}

// With 创建带字段的日志实例
func (l *ZerologLogger) With(fields ...Field) Logger {
	newLogger := l.logger.With()
	for _, field := range fields {
		newLogger = newLogger.Interface(field.Key, field.Value)
	}
	return &ZerologLogger{logger: newLogger.Logger()}
}

// Err 创建错误字段
func Err(err error) Field {
	return Field{Key: "error", Value: err.Error()}
}

// Str 创建字符串字段
func Str(key, value string) Field {
	return Field{Key: key, Value: value}
}

// Int 创建整数字段
func Int(key string, value int) Field {
	return Field{Key: key, Value: value}
}

// Bool 创建布尔字段
func Bool(key string, value bool) Field {
	return Field{Key: key, Value: value}
}

// Caller 创建调用者信息字段
func Caller() Field {
	_, file, line, ok := runtime.Caller(2)
	if !ok {
		return Field{Key: "caller", Value: "unknown"}
	}
	return Field{Key: "caller", Value: fmt.Sprintf("%s:%d", filepath.Base(file), line)}
}
