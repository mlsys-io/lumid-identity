FROM --platform=linux/amd64 golang:1.25-alpine AS builder
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download || true
COPY . .
RUN CGO_ENABLED=0 go build -o /out/identity ./cmd/identity

FROM --platform=linux/amd64 alpine:3.20
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app
COPY --from=builder /out/identity /app/identity
COPY configs/identity.yaml /app/configs/identity.yaml
ENV TZ=Asia/Singapore
EXPOSE 9900
ENTRYPOINT ["/app/identity", "-c", "/app/configs/identity.yaml"]
