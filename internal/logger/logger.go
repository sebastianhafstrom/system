package logger

import (
	"log/slog"
	"os"
)

var Logger *slog.Logger

func init() {
	handler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		AddSource: false,
		Level:     slog.LevelDebug,
	})

	Logger = slog.New(handler)

	slog.SetDefault(Logger)
	Logger.Debug("Debug log")
	Logger.Info("Info log")
	Logger.Warn("Warn log")
	Logger.Error("Error log")
}
