.PHONY: build test vet run docker-build docker-up docker-down

# Собрать все cmd-бинарники.
build:
	go build ./...

# Прогнать все тесты.
test:
	go test ./...

# Статический анализ.
vet:
	go vet ./...

# Запустить сервис локально.
run:
	go run ./cmd/piiproxy

# Собрать Docker-образ.
docker-build:
	docker build -t pii-proxy-deepseek .

# Поднять сервис в Docker (сборка + запуск).
docker-up:
	docker compose up -d --build

# Остановить сервис в Docker.
docker-down:
	docker compose down