# Use official Go image as the builder
FROM golang:1.24-alpine AS builder

# Set working directory
WORKDIR /app

# Copy Go modules and install dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the application code
COPY . .

# Build the application
RUN go build -o system cmd/api/main.go

# Final stage (smaller image)
FROM alpine:latest

# Set timezone (optional)
RUN apk --no-cache add tzdata

# Copy the compiled binary from the builder
COPY --from=builder /app/system /system

# Expose the application port
EXPOSE 8080

# Start the application
CMD ["/system"]