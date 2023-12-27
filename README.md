基于 `hyper` 、 `tls-listener ` 和 `rustls` 的http代理。

整体功能完全对标[Java版本HttpProxy](https://github.com/arloor/HttpProxy)。 内存仅为Java版本的十分之一，为20MB以下。

相比 `hyper`的[正向代理example](https://github.com/hyperium/hyper/blob/0.14.x/examples/http_proxy.rs)增加了以下特性：

1. proxy over tls特性( `over_tls=true` )：使用tls来对代理流量进行加密。
2. 每天定时加载tls证书，acme证书过期重新签发时不需要重启服务。
3. 支持Proxy-Authorization鉴权。
4. 开启Proxy-Authorization鉴权时，结合 `ask_for_auth=false` 配置防止嗅探。
5. 删除代理相关的header，以保持高匿。
6. 类Nginx的静态资源托管，可以搭建静态网站。

提及的参数详见[高级配置](#高级配置)

## 运行

```shell
cargo run --package rust_http_proxy --bin rust_http_proxy
```

## 高级配置

通过环境变量进行配置，相关环境变量及其默认值：

```shell
# 监听的端口
export port=3128
# 默认为空，表示不鉴权。格式为 "Basic Base64Encode(username:password)"，注意username和password用英文冒号连接再进行Base64编码（RFC 7617）。
# 例如 Basic dXNlcm5hbWU6cGFzc3dvcmQ= 
# 这由此命令生成： echo -n "username:passwrod" | base64
export basic_auth=
# 主动发起Proxy-Authenticate。在公网下推荐设置为false。
export ask_for_auth=true
# 是否使用tls，默认为http
export over_tls=false
# tls证书
export cert=cert.pem
# 私钥 pem格式
export raw_key=privkey.pem
# 日志文件路径，默认为/tmp/proxy.log
export log_dir=/tmp
export log_file=proxy.log
# 代替nginx的web服务器功能，展示http网站
export web_content_path=/usr/share/nginx/html
# Referer请求头处理
# 1. 图片资源的防盗链：针对png/jpeg/jpg等文件的请求，要求Request的Referer header要么为空，要么包含下面的值
# 2. 外链访问监控：如果Referer不包含下面的值，并且访问html资源时，req_from_out++，用于外链访问监控
export refer=
```

**SSL配置**

其中，tls证书(`cert`)和pem格式的私钥(`raw_key`)可以通过openssl命令一键生成：

```shell
openssl req -x509 -newkey rsa:4096 -sha256 -nodes -keyout /usr/share/rust_http_proxy/privkey.pem -out /usr/share/rust_http_proxy/cert.pem -days 3650 -subj "/C=cn/ST=hl/L=sd/O=op/OU=as/CN=example.com"
```

如需签名证书，请购买tls证书或免费解决方案（acme.sh等）

**测试TLS Proxy**

可以使用curl来测试

```shell
curl  https://google.com --proxy-user "username:passwrod" -x https://xxxx.com:port  --proxy-insecure
```

## 安装说明

### linux amd64 可执行文件

> 通过Github Action自动更新release，永远是最新版，可放心使用

```shell
curl -SLfO https://github.com/arloor/rust_http_proxy/releases/download/v1.0.0/rust_http_proxy_musl
install rust_http_proxy_musl /usr/local/bin/rust_http_proxy
rust_http_proxy
```

### Docker 安装 

> 通过Github Action自动更新release，永远是最新版，可放心使用

```shell
docker run --rm -it --name proxy --net host docker.io/arloor/rust_http_proxy
```

## 可观测

### Linux运行时的网速监控

在linux运行时，会监控网卡网速，并展示在 `/speed` 。

![](speed.png)

### Prometheus Exporter

提供了Prometheus的Exporter

```text
# HELP req_from_out Number of HTTP requests received.
# TYPE req_from_out counter
req_from_out_total{referer="all",path="all"} 4
# HELP proxy_access num proxy_access.
# TYPE proxy_access counter
# EOF
```

可以使用[此Grafana大盘Template](https://grafana.com/grafana/dashboards/20185-rust-http-proxy/)来创建Grafana大盘，效果如下

![Alt text](grafana-dashboard.png)

## 客户端
 
可以使用clash作为客户端，见：

- [clash for windows](https://github.com/Fndroid/clash_for_windows_pkg/releases)
- [clashX pro](https://install.appcenter.ms/users/clashx/apps/clashx-pro/distribution_groups/public)
- [ClashForAndroid](https://github.com/Kr328/ClashForAndroid/releases)

## 高匿实现

代理服务器收到的http请求有一些特征，如果代理服务器不能正确处理，则会暴露自己是一个代理。高匿代理就是能去除这些特征的代理。具体特征有三个：

- 代理服务器收到的request line中有完整url，即包含schema、host。而正常http请求的url只包含路径
- 代理服务器收到http header中有Proxy-Connection请求头，需要去掉
- 代理服务器收到http header中有Proxy-Authentication请求头，需要去掉

本代理能去除以上特征。下面是使用tcpdump测试的结果，分别展示代理服务器收到的http请求和nginx web服务器收到的http请求已验证去除以上特征。

代理服务器收到的消息：

![](traffic_at_proxy.png)

Nginx收到的消息：

![](traffic_at_nginx.png)

可以看到请求URL和`Proxy-Connection`都被正确处理了。


## 一些例子

- [tls-listener example](https://github.com/tmccombs/tls-listener/blob/main/examples/http.rs)
- [tls-listener change-certificate](https://github.com/tmccombs/tls-listener/blob/main/examples/http-change-certificate.rs)
- [hyper example http_proxy](https://github.com/hyperium/hyper/blob/master/examples/http_proxy.rs)
- [rustls async Acceptor for hyper v0.14](https://github.com/rustls/hyper-rustls/blob/286e1fa57ff5cac99994fab355f91c3454d6d83d/src/acceptor.rs)
- [rustls async Acceptor for hyper v1](https://github.com/Gelbpunkt/hyper-rustls/blob/3d88d7d76c2e91e39b028dbbb92db917aa051092/src/acceptor.rs)