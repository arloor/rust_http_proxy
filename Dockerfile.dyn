FROM docker.io/arloor/ubi-micro:latest
RUN cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime && echo "Asia/Shanghai" > /etc/timezone;
COPY target/x86_64-unknown-linux-gnu/release/rust_http_proxy /
ENTRYPOINT ["/rust_http_proxy"]