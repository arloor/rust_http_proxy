FROM docker.io/arloor/ubi-micro:latest
RUN cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime && echo "Asia/Shanghai" > /etc/timezone;
COPY target/release/x86_64-unknown-linux-gnu/rust_http_proxy /
ENTRYPOINT ["/rust_http_proxy"]