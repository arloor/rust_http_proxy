# FROM rockylinux:9.3
# RUN dnf install -y net-tools
# FROM redhat/ubi9-micro:9.2-9
# 设置时区为上海，ubi9-micro内置了tzdata https://catalog.redhat.com/software/containers/ubi9/ubi/615bcf606feffc5384e8452e?container-tabs=packages
FROM alpine:latest
RUN apk add --no-cache net-tools; \
    apk add --no-cache tzdata; \
    cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime; \
    echo "Asia/Shanghai" > /etc/timezone; \
    apk del tzdata
COPY target/release/rust_http_proxy /
ENTRYPOINT ["/rust_http_proxy"]