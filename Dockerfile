FROM alpine:3.18.2
# 设置时区为上海
#RUN apk add tzdata && cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime \
#    && echo "Asia/Shanghai" > /etc/timezone \
#    && apk del tzdata
#RUN mkdir /apps
COPY target/x86_64-unknown-linux-musl/release/rust_http_proxy /
CMD ["/rust_http_proxy"]