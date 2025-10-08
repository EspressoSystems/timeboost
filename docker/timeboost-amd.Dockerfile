FROM amazonlinux:2023

WORKDIR /app

RUN yum install -y tar gzip openssl protobuf-compiler git jq && yum clean all
RUN curl -L https://foundry.paradigm.xyz | bash && /root/.foundry/bin/foundryup
ENV PATH="/root/.foundry/bin:${PATH}"
RUN cp /root/.foundry/bin/forge /usr/local/bin/
RUN cp /root/.foundry/bin/cast /usr/local/bin/
RUN forge --version

RUN groupadd -r appgroup && useradd -r -g appgroup timeboostuser

COPY ./target/x86_64-unknown-linux-gnu/release/timeboost .
COPY ./target/x86_64-unknown-linux-gnu/release/yapper .
COPY ./target/x86_64-unknown-linux-gnu/release/register .
COPY ./target/x86_64-unknown-linux-gnu/release/deploy .
COPY ./target/x86_64-unknown-linux-gnu/release/block-maker .
COPY ./target/x86_64-unknown-linux-gnu/release/block-checker .
COPY ./target/x86_64-unknown-linux-gnu/release/mkconfig .

RUN mkdir -p /app/scripts
COPY ./scripts/ /app/scripts/

RUN mkdir -p /app/configs
COPY ./test-configs/docker/ /app/configs/


RUN chown -R timeboostuser:appgroup /app && chmod +x \
    /app/timeboost \
    /app/yapper \
    /app/register \
    /app/deploy \
    /app/block-maker \
    /app/block-checker \
    /app/mkconfig \
    /app/scripts/deploy-contract

USER timeboostuser

ENV RUST_LOG=sailfish=debug,timeboost=debug,cliquenet=error

CMD ["/app/timeboost"]
