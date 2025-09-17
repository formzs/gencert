package errors

import (
	"fmt"
)

// ErrorType 错误类型
type ErrorType int

const (
	// ConfigError 配置错误
	ConfigError ErrorType = iota
	// FileSystemError 文件系统错误
	FileSystemError
	// CertificateError 证书错误
	CertificateError
	// ValidationError 验证错误
	ValidationError
	// NetworkError 网络错误
	NetworkError
	// UnknownError 未知错误
	UnknownError
)

// GenCertError 自定义错误类型
type GenCertError struct {
	Type    ErrorType
	Message string
	Cause   error
}

// Error 实现error接口
func (e *GenCertError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("[%s] %s: %v", e.getTypeString(), e.Message, e.Cause)
	}
	return fmt.Sprintf("[%s] %s", e.getTypeString(), e.Message)
}

// Unwrap 解包错误
func (e *GenCertError) Unwrap() error {
	return e.Cause
}

// getTypeString 获取错误类型字符串
func (e *GenCertError) getTypeString() string {
	switch e.Type {
	case ConfigError:
		return "配置错误"
	case FileSystemError:
		return "文件系统错误"
	case CertificateError:
		return "证书错误"
	case ValidationError:
		return "验证错误"
	case NetworkError:
		return "网络错误"
	default:
		return "未知错误"
	}
}

// NewConfigError 创建配置错误
func NewConfigError(message string, cause ...error) *GenCertError {
	err := &GenCertError{
		Type:    ConfigError,
		Message: message,
	}
	if len(cause) > 0 {
		err.Cause = cause[0]
	}
	return err
}

// NewFileSystemError 创建文件系统错误
func NewFileSystemError(message string, cause ...error) *GenCertError {
	err := &GenCertError{
		Type:    FileSystemError,
		Message: message,
	}
	if len(cause) > 0 {
		err.Cause = cause[0]
	}
	return err
}

// NewCertificateError 创建证书错误
func NewCertificateError(message string, cause ...error) *GenCertError {
	err := &GenCertError{
		Type:    CertificateError,
		Message: message,
	}
	if len(cause) > 0 {
		err.Cause = cause[0]
	}
	return err
}

// NewValidationError 创建验证错误
func NewValidationError(message string, cause ...error) *GenCertError {
	err := &GenCertError{
		Type:    ValidationError,
		Message: message,
	}
	if len(cause) > 0 {
		err.Cause = cause[0]
	}
	return err
}

// NewNetworkError 创建网络错误
func NewNetworkError(message string, cause ...error) *GenCertError {
	err := &GenCertError{
		Type:    NetworkError,
		Message: message,
	}
	if len(cause) > 0 {
		err.Cause = cause[0]
	}
	return err
}

// IsConfigError 检查是否为配置错误
func IsConfigError(err error) bool {
	if genErr, ok := err.(*GenCertError); ok {
		return genErr.Type == ConfigError
	}
	return false
}

// IsFileSystemError 检查是否为文件系统错误
func IsFileSystemError(err error) bool {
	if genErr, ok := err.(*GenCertError); ok {
		return genErr.Type == FileSystemError
	}
	return false
}

// IsCertificateError 检查是否为证书错误
func IsCertificateError(err error) bool {
	if genErr, ok := err.(*GenCertError); ok {
		return genErr.Type == CertificateError
	}
	return false
}

// IsValidationError 检查是否为验证错误
func IsValidationError(err error) bool {
	if genErr, ok := err.(*GenCertError); ok {
		return genErr.Type == ValidationError
	}
	return false
}

// IsNetworkError 检查是否为网络错误
func IsNetworkError(err error) bool {
	if genErr, ok := err.(*GenCertError); ok {
		return genErr.Type == NetworkError
	}
	return false
}

// Wrap 包装错误
func Wrap(err error, message string) *GenCertError {
	if err == nil {
		return nil
	}

	var errorType ErrorType
	if genErr, ok := err.(*GenCertError); ok {
		errorType = genErr.Type
	} else {
		errorType = UnknownError
	}

	return &GenCertError{
		Type:    errorType,
		Message: message,
		Cause:   err,
	}
}