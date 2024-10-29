FROM ubuntu:jammy

ARG TARGETARCH

RUN apt-get update \
    && apt-get install -y curl libcurl4 wait-for-it tini \
    && rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["tini", "--"]