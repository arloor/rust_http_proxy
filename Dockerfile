FROM ubi9-micro:9.2
# 设置时区为上海，ubi9-micro内置了tzdata
RUN cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime && echo "Asia/Shanghai" > /etc/timezone
COPY target/x86_64-unknown-linux-musl/release/rust_http_proxy /
CMD ["/rust_http_proxy"]