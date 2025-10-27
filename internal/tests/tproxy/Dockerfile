FROM golang:1.21

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       iptables iproute2 ncat ca-certificates \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app/src/go-mmproxy
COPY . .

RUN CGO_ENABLED=0 go build -v -o /usr/local/bin/go-mmproxy

ENTRYPOINT ["bash", "internal/tests/tproxy/entrypoint.sh"]
