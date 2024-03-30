FROM redhat/ubi9-micro:9.2-9
RUN cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime && echo "Asia/Shanghai" > /etc/timezone;
COPY target/release/rust_http_proxy /
ENTRYPOINT ["/rust_http_proxy"]