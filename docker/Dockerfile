FROM node:20-bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends strace python3 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace
