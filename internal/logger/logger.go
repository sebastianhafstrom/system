package logger

import (
	"log/slog"
	"os"
)

var Logger *slog.Logger

func Init() {
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		AddSource: true,
		Level:     slog.LevelDebug,
	})

	Logger = slog.New(handler).With("app", "SebSystem")

	slog.SetDefault(Logger)
	Logger.Info("Logger with slog initialized")
}
