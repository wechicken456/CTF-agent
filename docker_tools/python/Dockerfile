FROM python:3.12.12-slim-bookworm

ENV DEBIAN_FRONTEND=noninteractive
ENV PATH="/workspace:${PATH}"

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl wget git netcat-openbsd \
    nmap socat file binutils \
    python3-dev build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

COPY ./requirements.txt /workspace/

RUN pip install --no-cache-dir -r /workspace/requirements.txt

CMD ["tail", "-f", "/dev/null"]

