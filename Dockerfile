FROM registry.access.redhat.com/ubi9-micro:9.2-9
# 设置时区为上海，ubi9-micro内置了tzdata https://catalog.redhat.com/software/containers/ubi9/ubi/615bcf606feffc5384e8452e?container-tabs=packages
RUN cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime && echo "Asia/Shanghai" > /etc/timezone
COPY target/x86_64-unknown-linux-musl/release/rust_http_proxy /
CMD ["/rust_http_proxy"]