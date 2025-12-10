FROM alpine:3.21

RUN apk add --no-cache \
    nmap nmap-scripts \
    netcat-openbsd \
    socat \
    tcpdump \
    curl \
    bind-tools

WORKDIR /workspace
CMD ["tail", "-f", "/dev/null"]

