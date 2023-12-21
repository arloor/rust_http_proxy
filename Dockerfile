# FROM rockylinux:9.3
# RUN dnf install -y net-tools
FROM redhat/ubi9-micro:9.2-9
# 设置时区为上海，ubi9-micro内置了tzdata https://catalog.redhat.com/software/containers/ubi9/ubi/615bcf606feffc5384e8452e?container-tabs=packages
RUN cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime && echo "Asia/Shanghai" > /etc/timezone
COPY target/release/rust_http_proxy /
CMD ["/rust_http_proxy"]