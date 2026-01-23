# Rust HTTP Proxy

[![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/arloor/rust_http_proxy)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/arloor/rust_http_proxy)

一个基于 Rust 构建的高性能、多功能 HTTP 代理服务器，使用 `hyper`、`axum` 和 `rustls` 实现。

## ✨ 核心特性

### 🚀 代理功能

- **正向代理**：支持 HTTP/HTTPS 代理，可通过用户名密码认证
- **反向代理**：支持灵活配置反向代理路由规则
- **链式代理**：通过 `--forward-bypass-url` 指定上游代理服务器
- **websocket**: 正向代理和反向代理均支持websocket

### 📁 静态文件服务

- **类 Nginx 托管**：完整的静态资源托管能力
- **压缩支持**：自动 gzip 压缩，减少传输流量
- **断点续传**：支持 Accept-Ranges 和断点续传（单 range）
- **防盗链**：基于 Referer 请求头的图片防盗链功能

### 🔒 安全与加密

- **TLS 加密代理**：支持 `--over-tls` 参数，对正向代理流量进行 TLS 加密
- **自动证书加载**：每天自动重新加载 TLS 证书，支持 ACME 证书自动续期，无需重启服务
- **高匿代理**：完整实现高匿代理，去除代理特征（详见[高匿实现](#高匿实现)）

### 📊 可观测性

- **Prometheus 集成**：提供完整的 Prometheus metrics 导出
- **网速监控**：Linux 平台支持实时网卡流量监控（`/net` 路径）
- **eBPF 支持**：可选 eBPF socket filter 进行高性能流量统计
- **Grafana 大盘**：提供开箱即用的 [Grafana 模板](https://grafana.com/grafana/dashboards/20185-rust-http-proxy/)

### 🔧 其他特性

- **多端口、多用户**：支持同时监听多个端口，配置多个用户认证
- **连接管理**：10 分钟空闲自动关闭连接，节省资源
- **跨平台**：支持 Linux、macOS、Windows，提供 Windows 服务模式

## 安装使用

### 方式一：Linux AMD64 可执行文件

```bash
curl -SLf https://us.arloor.dev/https://github.com/arloor/rust_http_proxy/releases/download/latest/rust_http_proxy -o /tmp/rust_http_proxy
install /tmp/rust_http_proxy /usr/bin/rust_http_proxy
/usr/bin/rust_http_proxy -p 7788
```

### 方式二：Docker 运行（推荐）

```bash
# 标准版本
docker run --rm -it --net host --pid host quay.io/arloor/rust_http_proxy -p 7788

# eBPF 增强版本
docker run --rm -it --privileged --net host --pid host quay.io/arloor/rust_http_proxy:bpf_static -p 7788
```

> 💡 Docker 镜像通过 GitHub Actions 自动构建，始终保持最新版本

### 方式三：从源码编译

```bash
# 克隆仓库
git clone https://github.com/arloor/rust_http_proxy.git
cd rust_http_proxy

# 标准编译
cargo build --release

# eBPF 增强版本（需要额外依赖）
cargo build --release --features bpf_vendored
```

### 快速测试

启动服务后，使用 curl 测试：

```bash
# 测试正向代理（HTTP）
curl http://ip.im/info -x http://localhost:7788

# 测试正向代理（HTTPS + 认证）
curl https://ip.im/info -U "username:password" -x https://localhost:7788 --proxy-insecure
```

## ⚙️ 配置说明

### 命令行参数

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

### 🔐 TLS/SSL 配置

#### 生成自签名证书（测试用）

```bash
openssl req -x509 -newkey rsa:4096 -sha256 -nodes \
  -keyout /usr/share/rust_http_proxy/privkey.pem \
  -out /usr/share/rust_http_proxy/cert.pem \
  -days 3650 \
  -subj "/C=cn/ST=hl/L=sd/O=op/OU=as/CN=example.com"
```

#### 使用正式证书

生产环境建议使用以下方式获取正式证书：

- 购买商业 TLS 证书
- 使用 [acme.sh](https://github.com/acmesh-official/acme.sh) 等工具申请 Let's Encrypt 免费证书

### 📂 静态文件托管配置

#### 全局配置

通过 `--web-content-path` 参数指定默认静态资源目录：

```bash
rust_http_proxy -p 7788 --web-content-path /var/www/html
```

#### 高级配置（基于域名和路径）

使用 `--location-config-file` 指定 YAML 配置文件，支持按域名、路径分别配置：

```yaml
# 针对特定域名的配置
example.com:
  - location: / # URL 路径前缀，默认 /
    static_dir: /usr/share/nginx/html # 静态资源目录

# 对所有域名生效的配置
default_host:
  - location: /static
    static_dir: /var/www/static
  - location: /downloads
    static_dir: /var/www/downloads
```

### 🔄 反向代理配置

使用 `--location-config-file` 配置反向代理规则：

```yaml
# 针对特定域名
api.example.com:
  - location: /api
    upstream:
      url_base: "https://backend.internal.com" # 上游服务器 URL
      version: "AUTO" # HTTP 版本: H1/H2/AUTO
      headers: # 可选：修改发送给上游的请求头
        Host: "#{host}" # #{host} 变量代表原始请求的 Host
        X-Custom-Header: "custom_value"
```

反向代理到上游的请求url构建方式如下：

```rust
let upstream_url = upstream.url_base.clone() + &path_and_query[location.len()..]; // upstream.url_base + 原始url_path去除location的部分
```

#### upstream 配置项说明

| 参数       | 说明                        | 可选值                      |
| ---------- | --------------------------- | --------------------------- |
| `url_base` | 上游服务器的基础 URL        | 任意有效 URL                |
| `version`  | HTTP 协议版本               | `H1`、`H2`、`AUTO`（默认）  |
| `headers`  | 覆盖/添加发送给上游的请求头 | 键值对，支持 `#{host}` 变量 |

### 🌐 内置反向代理功能

#### GitHub 资源代理

在国内无法访问 GitHub 时，可启用 GitHub 代理功能。通过在原始 URL 前添加 `https://YOUR_DOMAIN` 访问：

```bash
# 启动时添加参数
rust_http_proxy -p 7788 --enable-github-proxy
```

支持代理的 GitHub 域名：

- `raw.githubusercontent.com`
- `github.com`
- `gist.githubusercontent.com`
- `gist.github.com`
- `release-assets.githubusercontent.com`
- `objects.githubusercontent.com`

使用示例：

```bash
# 原始地址
https://raw.githubusercontent.com/user/repo/main/file.txt

# 代理后地址
https://YOUR_DOMAIN/https://raw.githubusercontent.com/user/repo/main/file.txt
```

#### 快捷反向代理

通过 `--append-upstream-url` 快速配置反向代理：

```bash
rust_http_proxy -p 7788 --append-upstream-url=https://cdnjs.cloudflare.com
```

访问方式：

```
https://YOUR_DOMAIN/https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js
```

等价于以下 YAML 配置：

````yaml
```yaml
default_host:
  - location: /https://cdnjs.cloudflare.com
    upstream:
      url_base: https://cdnjs.cloudflare.com
      version: AUTO
````

## 📊 可观测性与监控

### Prometheus Metrics

本项目内置 Prometheus Exporter，通过 `/metrics` 端点暴露指标。

> ⚠️ **注意**：如果设置了 `--users` 参数，访问 `/metrics` 时需要在 HTTP Header 中提供 Authorization，否则返回 `401 UNAUTHORIZED`。

#### 示例指标

```prometheus
# HELP req_from_out Number of HTTP requests received.
# TYPE req_from_out counter
req_from_out_total{referer="all",path="all"} 4

# HELP proxy_traffic num proxy_traffic.
# TYPE proxy_traffic counter
proxy_traffic_total 1048576
# EOF
```

### Grafana 可视化

推荐使用官方提供的 [Grafana Dashboard 模板](https://grafana.com/grafana/dashboards/20185-rust-http-proxy/)，快速搭建监控大盘。

**效果预览**：

![Grafana Dashboard 1](grafana-template1.png)
![Grafana Dashboard 2](grafana-template2.png)

### 实时网速监控（Linux）

在 Linux 平台运行时，访问 `/net` 路径可查看实时网卡流量监控。

**效果预览**：

![网速监控](speed.png)

## 🖥️ 客户端推荐

### Clash 系列

- [clash-verge-rev](https://github.com/clash-verge-rev/clash-verge-rev) - 跨平台 Clash GUI
- [ClashMetaForAndroid](https://github.com/MetaCubeX/ClashMetaForAndroid) - Android 平台
- [mihomo (clash-meta)](https://github.com/MetaCubeX/mihomo/tree/Meta) - 核心程序

### 作者自研客户端

- **Rust**: [sslocal](https://github.com/arloor/shadowsocks-rust) - Fork shadowsocks-rust
- **Golang**: [forward](https://github.com/arloor/forward)
- **Java**: [connect](https://github.com/arloor/connect)

## 🛠️ 高级功能

### Cargo Features

本项目支持多种编译特性，可根据需求选择：

#### 🔥 eBPF 增强（推荐）

使用 eBPF 技术统计网卡流量，提供更高性能和更详细的网络监控。

**编译方式**：

```bash
cargo build --release --features bpf_vendored
```

**系统依赖**：

Ubuntu 22.04：

```bash
apt-get install -y libbpf-dev bpftool cmake zlib1g-dev libelf-dev \
  pkg-config clang autoconf autopoint flex bison gawk make
```

CentOS Stream 9：

```bash
yum install -y libbpf zlib-devel elfutils-libelf-devel pkgconf-pkg-config \
  clang bpftool cmake autoconf gettext flex bison gawk make
```

> ⚠️ **注意**：仅在 `x86_64-unknown-linux-gnu` 平台测试通过

#### 🧠 Jemalloc 内存分配器

使用 jemalloc 替代系统默认内存分配器，提供更好的并发性能和减少内存碎片。

**编译方式**：

```bash
cargo build --release --features jemalloc
```

**特点**：

- ✅ 更高的并发分配能力
- ✅ 减少内存碎片
- ⚠️ 会缓存更多内存，`top` 命令中 RES 值可能较高

#### 🔐 AWS-LC-RS 加密后端

替换默认的 `ring` 加密库为 AWS 的 `aws-lc-rs`，提供更好的性能和 FIPS 合规性。

**编译方式**：

```bash
cargo build --release --no-default-features --features aws_lc_rs
```

**优势**：

1. ⚡ 性能更优（[Benchmark 测试](https://github.com/aochagavia/rustls-bench-results)）
2. 🏛️ 支持 [FIPS 140-2](https://csrc.nist.gov/pubs/fips/140-2/upd2/final) 合规要求

**额外依赖**：

```bash
apt-get install cmake  # Ubuntu/Debian
yum install cmake      # CentOS/RHEL
```

### 高匿代理实现

高匿代理（Elite Proxy）是指能够完全隐藏自身代理身份的代理服务器。本项目完整实现了高匿代理特性。

#### 代理特征清除

普通代理服务器收到的 HTTP 请求具有以下特征，本项目已全部处理：

1. **完整 URL 格式**
   - ❌ 普通代理：Request Line 包含完整 URL（schema + host + path）
   - ✅ 高匿处理：转换为仅包含路径的标准格式

2. **Proxy-Connection 请求头**
   - ❌ 普通代理：保留 `Proxy-Connection` 头
   - ✅ 高匿处理：自动删除

3. **Proxy-Authorization 请求头**
   - ❌ 普通代理：保留 `Proxy-Authorization` 头
   - ✅ 高匿处理：自动删除

#### 验证测试

使用 tcpdump 抓包验证，对比代理服务器和上游服务器收到的请求：

**代理服务器收到的原始请求**：

![代理服务器流量](traffic_at_proxy.png)

**上游 Nginx 服务器收到的处理后请求**：

![Nginx 服务器流量](traffic_at_nginx.png)

✅ **验证结论**：Request URL 已转换为标准路径格式，`Proxy-Connection` 等代理特征头已被移除。

## 🐳 容器化开发

### 本地测试

```bash
# 清理构建缓存
cargo clean

# 编译 eBPF 增强版本
cargo build -r --features bpf_vendored

# 构建测试镜像
podman build . -f Dockerfile.test -t test --net host

# 运行测试容器
podman run --rm -it --privileged --net host --pid host test
```

## 🪟 Windows 服务模式

### 编译 Windows 服务版本

```powershell
cargo build --bin rust_http_proxy_service --features winservice --release
```

### 安装与管理

#### 使用 sc.exe

```powershell
# 创建服务
sc.exe create rust_http_proxy binPath= "C:\path\to\rust_http_proxy_service.exe -p 7777 -u username:password"

# 启动服务
sc.exe start rust_http_proxy

# 设置自动启动
sc.exe config rust_http_proxy start= auto

# 停止服务
sc.exe stop rust_http_proxy

# 删除服务
sc.exe delete rust_http_proxy
```

#### 使用 PowerShell Cmdlet

```powershell
# 创建并配置服务
New-Service -Name "rust_http_proxy" `
  -BinaryPathName "C:\path\to\rust_http_proxy_service.exe -p 7777 -u username:password" `
  -StartupType Automatic `
  -Description "A HTTP proxy server based on Hyper and Rustls"

# 启动服务
Start-Service -Name "rust_http_proxy"

# 停止服务
Stop-Service -Name "rust_http_proxy"

# 删除服务
(Get-WmiObject -Class Win32_Service -Filter "Name='rust_http_proxy'").Delete()

# PowerShell 6.0+ 可使用
# Remove-Service -Name "rust_http_proxy"
```

## 📄 许可证

本项目采用双许可证：

- [LGPL-2.1-only](LICENSE.LGPL-2.1) OR [BSD-2-Clause](LICENSE.BSD-2-Clause)

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

## 📮 联系方式

- GitHub Issues: [arloor/rust_http_proxy/issues](https://github.com/arloor/rust_http_proxy/issues)
- 项目主页: [github.com/arloor/rust_http_proxy](https://github.com/arloor/rust_http_proxy)

---

⭐ 如果这个项目对你有帮助，请给一个 Star！
