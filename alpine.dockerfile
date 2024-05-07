FROM ubuntu
run apt update&&apt-get install -y curl gcc autoconf autopoint flex bison gawk make pkg-config automake libbpf-dev libz-dev libelf-dev pkg-config clang&& curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- --default-host x86_64-unknown-linux-gnu -y
run git clone https://github.com/arloor/rust_http_proxy.git /rust_http_proxy
WORKDIR /rust_http_proxy
ENV PATH="/root/.cargo/bin:${PATH}"
ENV RUSTFLAGS='-C target-feature=+crt-static'
ENTRYPOINT ["cargo","build","--release","-p","rust_http_proxy","--no-default-features","--features","aws_lc_rs,jemalloc,bpf_vendored","--target","x86_64-unknown-linux-gnu"]