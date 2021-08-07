package dbController

import (
	"fmt"
	"time"
)

type NonceDocument struct {
	NonceHash     string `bson:"hash"`
	RemoteAddress string `bson:"remoteAddress"`
	Time          int    `bson:"time"`
}

type UserDocument struct {
	Username string `bson:"username"`
	Email    string `bson:"email"`
	Enabled  bool   `bson:"enabled"`
	Admin    bool   `bson:"admin"`
}

type RequestLogData struct {
	TimeStamp    time.Time     `bson:"timestamp"`
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
	msg := fmt.Sprintf("%s - [%s] \"%s %s %s %d %s \"%s\" \"%s\"",
		rld.TimeStamp.Format(time.RFC1123),
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

type ErrorLogData struct {
	TimeStamp time.Time `bson:"timestamp"`
	Type      string    `bson:"type"`
	Message   string    `bson:"message"`
}

func (eld ErrorLogData) PrettyString() string {
	msg := fmt.Sprintf("%s - [%s] \"%s\"",
		eld.TimeStamp.Format(time.RFC1123),
		eld.Type,
		eld.Message,
	)

	return msg
}
