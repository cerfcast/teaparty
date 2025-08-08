FROM rust:latest AS builder
WORKDIR /usr/src/teaparty
COPY . .
RUN CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse cargo install --path .

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y iproute2 iputils-ping
COPY --from=builder /usr/local/cargo/bin/teaparty /usr/local/bin/teaparty
CMD ["teaparty"]
