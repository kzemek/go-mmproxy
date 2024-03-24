FROM golang:1.21 AS builder
RUN apt-get update && apt-get install -y iptables iproute2 && apt-get clean
WORKDIR /app/src/go-mmproxy
COPY . .
RUN CGO_ENABLED=0 go build -v
ENTRYPOINT ["sh", "-x", "docker-example/entrypoint.sh"]
