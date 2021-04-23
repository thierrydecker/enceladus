package main

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func main() {

}

func applicationLogger() *zap.Logger {
	config := zap.Config{
		Encoding:         "console",
		Level:            zap.NewAtomicLevelAt(zapcore.InfoLevel),
		OutputPaths:      []string{"stdout"},
		ErrorOutputPaths: []string{"stdout"},
		EncoderConfig: zapcore.EncoderConfig{
			MessageKey:   "message",
			LevelKey:     "level",
			EncodeLevel:  zapcore.CapitalColorLevelEncoder,
			TimeKey:      "time",
			EncodeTime:   zapcore.ISO8601TimeEncoder,
			CallerKey:    "caller",
			EncodeCaller: zapcore.ShortCallerEncoder,
		},
	}
	logger, err := config.Build()
	if err != nil {
		panic(err)
	}
	return logger
}
