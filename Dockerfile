FROM golang:1.22-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags "-X main.version=${VERSION} -X main.commit=$(git rev-parse --short HEAD)" \
    -o /bin/authplex \
    ./cmd/authplex

FROM gcr.io/distroless/static-debian12

COPY --from=builder /bin/authplex /bin/authplex

EXPOSE 8080

ENTRYPOINT ["/bin/authplex"]
