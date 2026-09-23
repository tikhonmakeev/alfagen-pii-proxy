# Многоэтапная сборка: первый этап компилирует бинарник из исходников,
# второй — кладёт его в минимальный базовый образ.

# Этап 1: сборка.
FROM golang:1.24@sha256:d2d2bc1c84f7e60d7d2438a3836ae7d0c847f4888464e7ec9ba3a1339a1ee804 AS builder
LABEL maintainer="pii-proxy-deepseek team"
LABEL org.opencontainers.image.title="pii-proxy"
WORKDIR /src

# Копируем модули и подтягиваем зависимости (кэшируется отдельно).
COPY go.mod go.sum ./
RUN go mod download

# Копируем исходники и собираем статический бинарник.
COPY cmd/piiproxy ./cmd/piiproxy
COPY internal ./internal
ARG TARGETARCH=amd64
ENV CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH}
RUN go build -trimpath -ldflags="-s -w" -o /piiproxy ./cmd/piiproxy

# Этап 2: минимальный runtime-образ.
FROM scratch
COPY --from=builder /piiproxy /piiproxy
COPY consumers.yaml /consumers.yaml

USER 65532:65532

ENV LISTEN_ADDR=0.0.0.0:8080
ENV METRICS_ADDR=0.0.0.0:9090

EXPOSE 8080 9090

ENTRYPOINT ["/piiproxy"]

HEALTHCHECK NONE
