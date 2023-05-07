基于 `hyper` 和 `tls-listener` 的http代理。

整体功能完全对标[Java版本HttpProxy](https://github.com/arloor/HttpProxy)。 内存仅为Java版本的十分之一，为20MB以下。

相比 `hyper`的[正向代理example](https://github.com/hyperium/hyper/blob/0.14.x/examples/http_proxy.rs)增加了以下特性：

1. proxy over tls特性(`over_tls=true`)：使用tls来对代理流量进行加密以**surf the global Internet**
2. 支持Proxy-Authorization鉴权。
3. 开启Proxy-Authorization鉴权时，结合`ask_for_auth=false`配置防止嗅探。
4. 删除代理相关的header，以保持高匿，例如`Proxy-Connection`等。

以上特性详见"高级配置"部分。

## 运行

```shell
cargo run --package rust_http_proxy --bin rust_http_proxy
```

## 高级配置

通过环境变量进行配置，相关环境变量及其默认值：

```shell
# 监听的端口
export port=3128
# 默认为空，表示不鉴权。格式为 Basic aGFsNkWSY3QXNBJjg4Jig5JikqKg==
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
```

其中，tls证书(`cert`)和pem格式的私钥(`raw_key`)可以通过openssl命令一键生成：

```shell
openssl req -x509 -newkey rsa:4096 -sha256 -nodes -keyout privkey.pem -out cert.pem -days 3650 -subj "/C=/ST=/L=/O=/OU=/CN=example.com"
```

如需签名证书，请购买tls证书或免费解决方案（acme.sh等）

## 安装说明

见[releases v0.1.0](https://github.com/arloor/rust_http_proxy/releases/tag/v0.1.0)

## 客户端

可以使用clash作为客户端，见：

- [clash for windows](https://github.com/Fndroid/clash_for_windows_pkg/releases)
- [clashX pro](https://install.appcenter.ms/users/clashx/apps/clashx-pro/distribution_groups/public)
- [ClashForAndroid](https://github.com/Kr328/ClashForAndroid/releases)