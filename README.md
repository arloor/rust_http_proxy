[![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/arloor/rust_http_proxy)

[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/arloor/rust_http_proxy)

基于 `hyper` 、 `axum` 、 `rustls` 的**静态资源托管服务器**、**正向代理**、**反向代理**、**API server**。

## 功能特性

1. 使用 tls 来对正向代理流量进行加密（`--over-tls`）。
2. 类 Nginx 的静态资源托管。支持 gzip 压缩。支持 Accept-Ranges 以支持断点续传（备注：暂不支持多 range，例如 `Range: bytes=0-100,100-` ）
3. 支持链式代理（通过--forward-bypass-url 指定上游代理服务器）
4. 支持反向代理。
5. 基于 Prometheus 的可观测，可以监控代理的流量、外链访问等。
6. 采集网卡上行流量，展示在 `/net` 路径下（读取 `/proc/net/dev` 或基于 `ebpf socket filter` ）
7. 支持多端口，多用户。
8. 每天定时加载 tls 证书，acme 证书过期重新签发时不需要重启服务。
9. 连接空闲（10 分钟没有 IO）自动关闭。

提及的参数详见[命令行参数](#命令行参数)

## 安装说明

### linux amd64 可执行文件

```shell
curl -SLf https://us.arloor.dev/https://github.com/arloor/rust_http_proxy/releases/download/latest/rust_http_proxy -o /tmp/rust_http_proxy
install /tmp/rust_http_proxy /usr/bin/rust_http_proxy
/usr/bin/rust_http_proxy -p 7788
```

### Docker 安装

> 通过 Github Action 自动更新 release，永远是最新版，可放心使用

```shell
docker run --rm -it --net host --pid host docker.io/arloor/rust_http_proxy -p 7788
```

### ebpf 版本安装

```bash
curl -SLf https://us.arloor.dev/https://github.com/arloor/rust_http_proxy/releases/download/latest/rust_http_proxy_bpf_static -o /tmp/rust_http_proxy
install /tmp/rust_http_proxy /usr/bin/rust_http_proxy
/usr/bin/rust_http_proxy -p 7788
```

或者

```bash
docker run --rm -it --privileged --net host --pid host docker.io/arloor/rust_http_proxy:bpf_static -p 7788
```

## 命令行参数

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
          指定上游代理服务器
      --ipv6-first <IPV6_FIRST>
          优先使用 IPv6 进行连接。true表示IPv6优先，false表示IPv4优先，不设置则保持DNS原始顺序 [possible values: true, false]
  -h, --help
          Print help
```

### SSL 配置

其中，tls 证书(`--cert`)和 pem 格式的私钥(`--key`)可以通过 openssl 命令一键生成：

```bash
openssl req -x509 -newkey rsa:4096 -sha256 -nodes -keyout /usr/share/rust_http_proxy/privkey.pem -out /usr/share/rust_http_proxy/cert.pem -days 3650 -subj "/C=cn/ST=hl/L=sd/O=op/OU=as/CN=example.com"
```

如需签名证书，请购买 tls 证书或免费解决方案（acme.sh 等）

测试 TLS Proxy 可以使用 curl （7.52.0 以上版本）:

```bash
curl https://ip.im/info -U "username:password" -x https://localhost:7788  --proxy-insecure
```

### 静态文件托管配置

1. 可以使用 `--web-content-path <WEB_CONTENT_PATH>` 参数定指默认静态资源目录。

2. 可以使用`--location-config-file` 通过配置文件指定特定域名、特定 url 的静态资源目录。

```yaml
YOUR_DOMAIN:
  - location: / # 默认为 /
    static_dir: /usr/share/nginx/html # 静态资源目录
```

> 如果 `YOUR_DOMAIN` 填 `default_host` 则对所有的域名生效。

### 反向代理配置

可以使用`--location-config-file` 通过配置文件指定特定域名、特定 url 的反向代理配置。

```yaml
YOUR_DOMAIN:
  - location: / # 默认为 /
    upstream:
      url_base: "https://www.baidu.com" # 上游服务器的基础 URL
      version: "H1" # 可以填H1、H2、AUTO，默认为AUTO
      headers:
        Host: "#{host}" # 可选，覆盖发送给上游服务器的请求头
        Custom-Header: "custom_value" # 其他自定义请求头
```

> 如果 `YOUR_DOMAIN` 填 `default_host` 则对所有的域名生效。

#### upstream 配置说明

- `url_base`: 上游服务器的基础 URL
- `version`: HTTP 版本，可选值为 `H1`、`H2`、`AUTO`，默认为 `AUTO`
- `headers`: 可选参数，用于覆盖发送给上游服务器的请求头。 支持变量 `#{host}`，分别表示原请求的 Host。

#### 例子 1: Github Proxy

在 github 原始 url 前加上`https://YOUR_DOMAIN`，以便在国内访问 raw.githubusercontent.com、github.com 和 gist.githubusercontent.com

启动参数中增加 `--enable-github-proxy`，相当于以下配置：

```yaml
default_host:
  - location: /https://release-assets.githubusercontent.com
    upstream:
      url_base: https://release-assets.githubusercontent.com
      version: AUTO
  - location: /https://raw.githubusercontent.com
    upstream:
      url_base: https://raw.githubusercontent.com
      version: AUTO
  - location: /https://objects.githubusercontent.com
    upstream:
      url_base: https://objects.githubusercontent.com
      version: AUTO
  - location: /https://github.com
    upstream:
      url_base: https://github.com
      version: AUTO
  - location: /https://gist.githubusercontent.com
    upstream:
      url_base: https://gist.githubusercontent.com
      version: AUTO
  - location: /https://gist.github.com
    upstream:
      url_base: https://gist.github.com
      version: AUTO
```

#### 例子 2： 反向代理https://cdnjs.cloudflare.com

启动参数中增加 `--append-upstream-url=https://cdnjs.cloudflare.com`，相当于以下配置：

```yaml
default_host:
  - location: /https://cdnjs.cloudflare.com
    upstream:
      url_base: https://cdnjs.cloudflare.com
      version: AUTO
```

## 可观测

### Prometheus Exporter

提供了 Prometheus 的 Exporter。如果设置了`--users`参数，则需要在 header 中设置 authorization，否则会返回`401 UNAUTHORIZED`。

```text
# HELP req_from_out Number of HTTP requests received.
# TYPE req_from_out counter
req_from_out_total{referer="all",path="all"} 4
# HELP proxy_traffic num proxy_traffic.
# TYPE proxy_traffic counter
# EOF
```

可以使用[此 Grafana 大盘 Template](https://grafana.com/grafana/dashboards/20185-rust-http-proxy/)来创建 Grafana 大盘，效果如下

![alt text](grafana-template1.png)
![alt text](grafana-template2.png)

### Linux 运行时的网速监控

在 linux 运行时，会监控网卡网速，并展示在 `/net` 。

![](speed.png)

## 客户端

- Clash 系列
  - [clash-verge-rev](https://github.com/clash-verge-rev/clash-verge-rev)
  - [ClashMetaForAndroid](https://github.com/MetaCubeX/ClashMetaForAndroid)
  - [mihomo(clash-meta)](https://github.com/MetaCubeX/mihomo/tree/Meta)
- 自研玩具
  - Rust：[sslocal(fork shadowsocks-rust)](https://github.com/arloor/shadowsocks-rust)
  - Golang：[forward](https://github.com/arloor/forward)
  - Java: [connect](https://github.com/arloor/connect)

## Cargo Features

### bpf

使用 ebpf 来统计网卡出流量，仅在 `x86_64-unknown-linux-gnu` 上测试过。激活方式:

```bash
cargo build --features bpf
```

需要安装 `libbpf-rs` 所需的依赖：

**ubuntu 22.04 安装：**

```bash
apt-get install -y libbpf-dev bpftool cmake zlib1g-dev libelf-dev pkg-config clang autoconf autopoint flex bison gawk make
```

**centos stream 9 安装：**

```bash
yum install -y libbpf zlib-devel elfutils-libelf-devel pkgconf-pkg-config clang bpftool cmake autoconf gettext flex bison gawk make
```

### jemalloc

拥有更高的并发分配能力和减少内存碎片，不过会 buffer 更多的内存，因此 top 中 RES 数值会有上升。激活方式：

```bash
cargo build --features jemalloc
```

### aws_lc_rs

`aws_lc_rs` 和 `ring` 是 `rustls` 的两个加密后端。本项目默认使用 `ring` 作为加密后端，也可选择[aws_lc_rs](https://crates.io/crates/aws-lc-rs)作为加密后端。`aws_lc_rs` 相比 ring 主要有两点优势:

1. 在[rustls 的 benchmark 测试](https://github.com/aochagavia/rustls-bench-results)中，`aws_lc_rs` 的性能要优于 `ring` 。
2. 支持美国联邦政府针对加密提出的[fips 要求](https://csrc.nist.gov/pubs/fips/140-2/upd2/final)。

不过，使用 `aws_lc_rs` 会增加一些编译难度，需要额外做以下操作：

| 依赖的包 | 是否必须 | 安装方式                |
| -------- | -------- | ----------------------- |
| `cmake`  | 必须     | `apt-get install cmake` |

激活方式：

```bash
cargo build --no-default-features --features aws_lc_rs
```

## 高匿实现

代理服务器收到的 http 请求有一些特征，如果代理服务器不能正确处理，则会暴露自己是一个代理。高匿代理就是能去除这些特征的代理。具体特征有三个：

- 代理服务器收到的 request line 中有完整 url，即包含 schema、host。而正常 http 请求的 url 只包含路径
- 代理服务器收到 http header 中有 Proxy-Connection 请求头，需要去掉
- 代理服务器收到 http header 中有 Proxy-Authentication 请求头，需要去掉

本代理能去除以上特征。下面是使用 tcpdump 测试的结果，分别展示代理服务器收到的 http 请求和 nginx web 服务器收到的 http 请求已验证去除以上特征。

代理服务器收到的消息：

![](traffic_at_proxy.png)

Nginx 收到的消息：

![](traffic_at_nginx.png)

可以看到请求 URL 和`Proxy-Connection`都被正确处理了。

## 容器测试

```bash
cargo clean
cargo build -r --features bpf_vendored
podman build . -f Dockerfile.test -t test --net host
podman run --rm -it --privileged --net host --pid host test
```

## 以 windows 服务运行

### 编译 windows 服务版二进制文件

```powershell
cargo build --bin rust_http_proxy_service --features winservice --release
```

### 创建、启动 windows 服务

使用 `sc.exe`：

```powershell
sc.exe create rust_http_proxy binPath= "path\to\rust_http_proxy_service.exe -p 7777  -u username:password"
sc.exe start rust_http_proxy
sc.exe config rust_http_proxy start= auto
```

或使用 PowerShell cmdlet：

```powershell
New-Service -Name "rust_http_proxy" -BinaryPathName "path\to\rust_http_proxy_service.exe -p 7777 -u username:password" -StartupType Automatic -Description "A HTTP proxy server based on Hyper and Rustls, which features TLS proxy and static file serving"
Start-Service -Name "rust_http_proxy"
```

### 停止、删除 windows 服务

使用 `sc.exe`：

```powershell
sc.exe stop rust_http_proxy
sc.exe delete rust_http_proxy
```

或使用 PowerShell cmdlet：

```powershell
Stop-Service -Name "rust_http_proxy"
(Get-WmiObject -Class Win32_Service -Filter "Name='rust_http_proxy'").Delete()

# Remove-Service -Name "rust_http_proxy"  # 需要 PowerShell 6.0+
```
