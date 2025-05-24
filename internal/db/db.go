package db

import (
	"database/sql"

	_ "github.com/lib/pq"

	"github.com/sebastianhafstrom/system/internal/logger"
)

const connStr = "postgresql://user:password@localhost:5400/mydb?sslmode=disable"

func SetupDB() *sql.DB {
	log := logger.Logger
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Error("failed to setup DB", "error", err)
		return nil
	}

	err = db.Ping()
	if err != nil {
		log.Error("failed to ping db", "error", err)
		return nil
	}

	log.Info("DB setup succesfully")
	return db
}
