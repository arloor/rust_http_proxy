# 命令行参数

`rust_http_proxy` 的全部命令行参数如下（`rust_http_proxy --help` 输出）：

```shell
$ rust_http_proxy --help
A HTTP proxy server based on Hyper and Rustls, which features TLS proxy and static file serving

Usage: rust_http_proxy [OPTIONS]

Options:
      --log-dir <LOG_DIR>
          [default: /tmp]
      --log-file <LOG_FILE>
          [default: proxy.log]
  -p, --port <PORT>
          可以多次指定来实现多端口
           [default: 3128]
      --host <IP>
          指定监听 IP，例如 127.0.0.1、0.0.0.0、::1。未指定时默认监听 [::]
  -c, --cert <CERT>
          [default: cert.pem]
  -k, --key <KEY>
          [default: privkey.pem]
  -u, --users <USER>
          默认为空，表示不鉴权。
          格式为 'username:password'
          可以多次指定来实现多用户
  -w, --web-content-path <WEB_CONTENT_PATH>
          静态文件托管的根目录
      --static-auth-users <USER>
          --web-content-path 默认静态资源受保护路径的 Basic 认证用户，独立于 --users。
          格式为 'username:password'
          可以多次指定来实现多用户。不指定 --static-auth-path-prefix 时保护整个默认静态目录
      --static-auth-path-prefix <PATH_PREFIX>
          静态资源需要 Basic 认证的 URL 路径前缀，例如 /private 或 /downloads/secret
          可以多次指定，命中任意前缀都会要求认证。需要配合 --static-auth-users 使用
      --static-cache-max-age <SECONDS>
          未被 Basic 认证保护的静态资源响应的 Cache-Control max-age 秒数。
          被认证保护的路径始终返回 Cache-Control: private, no-store，防止 CDN 等共享缓存缓存认证内容
          [default: 600]
  -r, --referer-keywords-to-self <REFERER>
          Http Referer请求头处理
          1. 图片资源的防盗链：针对png/jpeg/jpg等文件的请求，要求Request的Referer header要么为空，要么包含配置的值
          2. 外链访问监控：如果Referer不包含配置的值，并且访问html资源时，Prometheus counter req_from_out++，用于外链访问监控
          可以多次指定，也可以不指定
      --never-ask-for-auth
          if enable, never send '407 Proxy Authentication Required' to client。
          当作为正向代理使用时建议开启，否则有被嗅探的风险。
      --allow-serving-network <CIDR>
          允许访问静态文件托管的网段白名单，格式为CIDR，例如: 192.168.1.0/24, 10.0.0.0/8
          可以多次指定来允许多个网段
          如未设置任何网段，则允许所有IP访问静态文件
  -o, --over-tls
          if enable, proxy server will listen on https
      --location-config-file <FILE_PATH>
          静态文件托管和反向代理的配置文件
      --enable-github-proxy
          是否开启github proxy
      --append-upstream-url <https://example.com>
          便捷反向代理配置
          例如：--append-upstream-url=https://cdnjs.cloudflare.com
          则访问 https://your_domain/https://cdnjs.cloudflare.com 会被代理到 https://cdnjs.cloudflare.com
      --forward-bypass-url <https://username:password@example.com:123>
          指定上游代理服务器。正向代理、非 MITM CONNECT 隧道、MITM 解密后的上游 HTTPS/WSS 请求均会经该父代理转发
      --ipv6-first <IPV6_FIRST>
          优先使用 IPv6 进行连接。true表示IPv6优先，false表示IPv4优先，不设置则保持DNS原始顺序 [possible values: true, false]
      --mitm-domain-suffix <SUFFIX>
          允许进行 HTTPS MITM 的域名后缀，可以多次指定。例如 example.com 会匹配 example.com 和 *.example.com
      --mitm-ca-cert <CERT>
          MITM 动态签发证书使用的 CA 证书 PEM 文件
      --mitm-ca-key <KEY>
          MITM 动态签发证书使用的 CA 私钥 PEM 文件
      --mitm-dump
          强制开启 MITM 明文抓取，并禁止通过控制台修改该开关（不向日志打印明文）
      --mitm-db-file <FILE_PATH>
          MITM 管理与明文记录 SQLite 文件。默认使用 <log-dir>/mitm.sqlite3
      --mitm-max-records <MITM_MAX_RECORDS>
          新 MITM 数据库的默认记录数量上限 [default: 1000]
      --mitm-body-limit-bytes <MITM_BODY_LIMIT_BYTES>
          新 MITM 数据库中单个请求或响应 body 的默认抓取字节上限 [default: 1048576]
      --mitm-stub-config-file <FILE_PATH>
          MITM stub YAML 配置文件，按 authority + path 返回静态响应或转发到 HTTP/HTTPS upstream
  -h, --help
          Print help
```

各参数的详细使用方式请参考对应的功能文档：

- TLS 相关（`--cert`、`--key`、`--over-tls`）：[TLS/SSL 配置](tls.md)
- MITM 相关（`--mitm-*`）：[HTTPS MITM](mitm.md)
- 静态托管相关（`--web-content-path`、`--static-*`、`--allow-serving-network`、`--referer-keywords-to-self`）：[静态文件托管](static-file-serving.md)
- 反向代理相关（`--location-config-file`、`--enable-github-proxy`、`--append-upstream-url`）：[反向代理](reverse-proxy.md)
