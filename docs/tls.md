# TLS/SSL 配置

`rust_http_proxy` 支持 `--over-tls` 参数，对正向代理流量进行 TLS 加密（代理服务器监听 HTTPS）。证书由 `--cert` 和 `--key` 参数指定，程序每天自动重新加载 TLS 证书，支持 ACME 证书自动续期，无需重启服务。

## 生成自签名证书（测试用）

```bash
mkdir -p /usr/share/rust_http_proxy
openssl req -x509 -newkey rsa:4096 -sha256 -nodes \
  -keyout /usr/share/rust_http_proxy/privkey.pem \
  -out /usr/share/rust_http_proxy/cert.pem \
  -days 3650 \
  -subj "/C=cn/ST=hl/L=sd/O=op/OU=as/CN=example.com"
```

## 使用正式证书

生产环境建议使用以下方式获取正式证书：

- 购买商业 TLS 证书
- 使用 [acme.sh](https://github.com/acmesh-official/acme.sh) 等工具申请 Let's Encrypt 免费证书

## 测试 TLS 代理

```bash
# 启动 TLS 加密的正向代理
rust_http_proxy -p 7788 --over-tls \
  -c /usr/share/rust_http_proxy/cert.pem \
  -k /usr/share/rust_http_proxy/privkey.pem \
  -u username:password

# 使用 curl 测试（自签证书需要 --proxy-insecure）
curl https://ip.im/info -U "username:password" -x https://localhost:7788 --proxy-insecure
```
