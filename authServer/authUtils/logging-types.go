package authUtils

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

/****************************************************************************************
* LoggingError
****************************************************************************************/
type LoggingError struct{ ErrMsg string }

func (err LoggingError) Error() string { return err.ErrMsg }
func NewLoggingError(msg string) error { return LoggingError{msg} }

/****************************************************************************************
* LogData
****************************************************************************************/
type LogData interface {
	PrettyString() string
}

/****************************************************************************************
* RequestLogData
****************************************************************************************/
type RequestLogData struct {
	Timestamp    time.Time     `bson:"timestamp"`
	Type         string        `bson:"type"`
	ClientIP     string        `bson:"clientIP"`
	Method       string        `bson:"method"`
	Path         string        `bson:"path"`
	Protocol     string        `bson:"protocol"`
	StatusCode   int           `bson:"statusCode"`
	Latency      time.Duration `bson:"latency"`
	UserAgent    string        `bson:"userAgent"`
	ErrorMessage string        `bson:"errorMessage"`
}

func (rld RequestLogData) PrettyString() string {
	msg := fmt.Sprintf("%s - [%s] %s %s %s %d %s \"%s\" \"%s\"",
		rld.Timestamp.Format(time.RFC1123),
		rld.ClientIP,
		rld.Method,
		rld.Path,
		rld.Protocol,
		rld.StatusCode,
		rld.Latency,
		rld.UserAgent,
		rld.ErrorMessage,
	)

	return msg
}

/****************************************************************************************
* InfoLogData
****************************************************************************************/
type InfoLogData struct {
	Timestamp time.Time `bson:"timestamp"`
	Type      string    `bson:"type"`
	Message   string    `bson:"message"`
}

func (ild InfoLogData) PrettyString() string {
	msg := fmt.Sprintf("%s - [%s] \"%s\"",
		ild.Timestamp.Format(time.RFC1123),
		ild.Type,
		ild.Message,
	)

	return msg
}

/****************************************************************************************
* AuthLogger
****************************************************************************************/
type AuthLogger interface {
	AddRequestLog(log *RequestLogData) error
	AddInfoLog(log *InfoLogData) error
}

/****************************************************************************************
* FileLogger
****************************************************************************************/
type FileLogger struct {
	FilePath   string
	FileName   string
	FileHandle *os.File
}

func (fl *FileLogger) AddRequestLog(log *RequestLogData) error {
	err := fl.WriteLog(log)

	return err
}

func (fl *FileLogger) AddInfoLog(log *InfoLogData) error {
	err := fl.WriteLog(log)

	return err
}

func (fl *FileLogger) WriteLog(log LogData) error {
	if fl.FileHandle == nil {
		return NewLoggingError("fileHandle is nil (no file handle exists)")
	}

	_, err := fl.FileHandle.WriteString(log.PrettyString() + "\n")

	return err
}

func MakeNewFileLogger(path string, name string) *FileLogger {
	print("Making New File Logger \n")
	fl := FileLogger{
		FileName: name,
		FilePath: path,
	}

	var handle *os.File
	var handleErr error
	fullPath := filepath.Join(path, name)

	var pathErr error

	if _, err := os.Stat(path); os.IsNotExist(err) {
		pathErr = os.MkdirAll(path, 0764)
	}

	// We return the FileLogger with FileHandle set to nil
	if pathErr != nil {
		// do something
		return &fl
	}

	// file, _ := os.Create("gin.log")
	handle, handleErr = os.OpenFile(fullPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)

	fmt.Println(handleErr)

	fl.FileHandle = handle

	fmt.Println(fl.FileHandle == nil)

	return &fl
}

/****************************************************************************************
* ConsoleLogger
****************************************************************************************/
type ConsoleLogger struct {
	LogPath  string
	FileName string
}

func (cl ConsoleLogger) AddRequestLog(log RequestLogData) error {
	return nil
}

func (cl ConsoleLogger) AddInfoLog(log *InfoLogData) error {
	return nil
}
