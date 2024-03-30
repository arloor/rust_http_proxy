FROM redhat/ubi9-micro:9.2-9
RUN cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime; \
    echo "Asia/Shanghai" > /etc/timezone;
# 设置时区为上海，ubi9-micro内置了tzdata https://catalog.redhat.com/software/containers/ubi9/ubi/615bcf606feffc5384e8452e?container-tabs=packages
# FROM alpine:latest
# RUN apk add --no-cache net-tools; \
#     apk add --no-cache tzdata; \
#     cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime; \
#     echo "Asia/Shanghai" > /etc/timezone; \
#     apk del tzdata
COPY target/x86_64-unknown-linux-musl/release/rust_http_proxy /
ENTRYPOINT ["/rust_http_proxy"]