FROM golang:1.27.2-alpine AS builder
WORKDIR /app

# Dependencias
COPY go.mod go.sum ./
RUN go mod download

# Código
COPY . .

# Build
RUN CGO_ENABLED=0 GOOS=linux go build -o server ./cmd/server

# Imagen final
FROM alpine:3.22
WORKDIR /app
COPY --from=builder /app/server /app/server

# Usa la var que lee tu main.go
ENV SERVICE_PORT=8080
ENV SERVICE_NAME=rac-auth-service

EXPOSE 8080
ENTRYPOINT ["/app/server"]

HEALTHCHECK --interval=15s --timeout=3s --start-period=15s CMD wget -q -O /dev/null http://127.0.0.1:8080/ready || exit 1
