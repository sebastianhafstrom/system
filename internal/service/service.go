package service

import "github.com/sebastianhafstrom/system/internal/logger"

func ServiceFunc() {
	log := logger.Logger
	log.Info("Hello from the ServiceFunc")
}
