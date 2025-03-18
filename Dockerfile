FROM golang:1.23 AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY . .
RUN go test ./...
RUN CGO_ENABLED=0 GOOS=linux go build -o oidc .

FROM apache/apisix:3.11.0-debian
USER root
COPY ./config.yaml /usr/local/apisix/conf/config.yaml
RUN chmod 755 /usr/local/apisix/conf/config.yaml && chown apisix:apisix /usr/local/apisix/conf/config.yaml
USER apisix
COPY --from=builder /app/oidc /usr/local/apisix/plugins/
