FROM golang:1.25

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl wget ca-certificates \
    && rm -rf /var/lib/apt/lists/*


RUN curl -L https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_amd64.tar.gz | tar xz -C /usr/local/bin 

RUN go install github.com/OJ/gobuster/v3@latest

RUN mkdir -p /opt/wordlist
WORKDIR /workspace
CMD ["tail", "-f", "/dev/null"]

