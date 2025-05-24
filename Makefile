run:
	go run ./cmd/api/main.go

run-docker:
	docker-compose up -d --build

test:
	go test ./... -v


DB_DSN = "postgres://user:password@localhost:5400/mydb?sslmode=disable"
MIGRATIONS_DIR = db/migrations

# Install Goose (run once)
install-goose:
	go install github.com/pressly/goose/v3/cmd/goose@latest

# Create a new SQL migration file
new-migration:
ifndef NAME
	$(error Usage: make new-migration NAME=your_migration_name)
endif
	goose -dir $(MIGRATIONS_DIR) create $(NAME) sql

# Apply all pending migrations
migrate-up:
	goose -dir $(MIGRATIONS_DIR) postgres $(DB_DSN) up

# Roll back the last migration
migrate-down:
	goose -dir $(MIGRATIONS_DIR) postgres $(DB_DSN) down

# Roll back all migrations (be careful in production!)
migrate-reset:
	goose -dir $(MIGRATIONS_DIR) postgres $(DB_DSN) reset

# Check migration status
migrate-status:
	goose -dir $(MIGRATIONS_DIR) postgres $(DB_DSN) status