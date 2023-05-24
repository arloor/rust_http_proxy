基于 `hyper` 和 `tls-listener` 的http代理。

整体功能完全对标[Java版本HttpProxy](https://github.com/arloor/HttpProxy)。 内存仅为Java版本的十分之一，为20MB以下。

相比 `hyper`的[正向代理example](https://github.com/hyperium/hyper/blob/0.14.x/examples/http_proxy.rs)增加了以下特性：

1. proxy over tls特性( `over_tls=true` )：使用tls来对代理流量进行加密以访问国际互联网。
2. 支持Proxy-Authorization鉴权。
3. 开启Proxy-Authorization鉴权时，结合 `ask_for_auth=false` 配置防止嗅探。
4. 删除代理相关的header，以保持高匿。
5. 对于浏览器访问，表现得和nginx相似，可用于网站服务器

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
# 默认为空，表示不鉴权。格式为 "Basic Base64Encode(username:password)"，注意username和password用英文冒号连接再进行Base64编码（RFC 7617）。例如 Basic dXNlcm5hbWU6cGFzc3dvcmQ=
export basic_auth=""
# 主动发起Proxy-Authenticate。在公网下推荐设置为false。
export ask_for_auth=true
# 是否使用tls，默认为http
export over_tls=false     
# tls证书
export cert=cert.pem
# 私钥 pem格式
export raw_key=privkey.pem
# 日志文件路径
export log_path=proxy.log 
# 代替nginx的web服务器功能，展示http网站
export web_content_path=/usr/share/nginx/html
```

其中，tls证书(`cert`)和pem格式的私钥(`raw_key`)可以通过openssl命令一键生成：

```shell
openssl req -x509 -newkey rsa:4096 -sha256 -nodes -keyout /usr/share/rust_http_proxy/privkey.pem -out /usr/share/rust_http_proxy/cert.pem -days 3650 -subj "/C=cn/ST=hl/L=sd/O=op/OU=as/CN=example.com"
```

如需签名证书，请购买tls证书或免费解决方案（acme.sh等）

## 安装说明

见[releases v0.2.0](https://github.com/arloor/rust_http_proxy/releases/tag/v0.2.0)

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