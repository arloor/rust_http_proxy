# Rust HTTP Proxy

[![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/arloor/rust_http_proxy)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/arloor/rust_http_proxy)

一个基于 Rust 构建的高性能、多功能 HTTP 代理服务器，使用 `hyper`、`axum` 和 `rustls` 实现。

## ✨ 核心特性

### 🚀 代理功能

- **正向代理**：支持 HTTP/HTTPS 代理，可通过用户名密码认证
- **HTTPS MITM**：可使用自定义 CA 动态签发目标域名证书并解密转发（详见 [HTTPS MITM](docs/mitm.md)）
- **反向代理**：支持灵活配置反向代理路由规则（详见 [反向代理](docs/reverse-proxy.md)）
- **链式代理**：通过 `--forward-bypass-url` 指定上游代理服务器
- **websocket**: 正向代理和反向代理均支持websocket

### 📁 静态文件服务

- **类 Nginx 托管**：完整的静态资源托管能力（详见 [静态文件托管](docs/static-file-serving.md)）
- **压缩支持**：自动 gzip 压缩，减少传输流量
- **断点续传**：支持 Accept-Ranges 和断点续传（单 range）
- **防盗链**：基于 Referer 请求头的图片防盗链功能

### 🔒 安全与加密

- **TLS 加密代理**：支持 `--over-tls` 参数，对正向代理流量进行 TLS 加密（详见 [TLS/SSL 配置](docs/tls.md)）
- **自动证书加载**：每天自动重新加载 TLS 证书，支持 ACME 证书自动续期，无需重启服务
- **高匿代理**：完整实现高匿代理，去除代理特征（详见 [高匿代理实现](docs/elite-proxy.md)）

### 📊 可观测性

- **Prometheus 集成**：提供完整的 Prometheus metrics 导出（详见 [可观测性与监控](docs/observability.md)）
- **网速监控**：Linux 平台支持实时网卡流量监控（`/net` 路径）
- **eBPF 支持**：可选 eBPF socket filter 进行高性能流量统计
- **Grafana 大盘**：提供开箱即用的 [Grafana 模板](https://grafana.com/grafana/dashboards/20185-rust-http-proxy/)

### 🔧 其他特性

- **多端口、多用户**：支持同时监听多个端口，配置多个用户认证
- **连接管理**：10 分钟空闲自动关闭连接，节省资源
- **跨平台**：支持 Linux、macOS、Windows，提供 [Windows 服务模式](docs/windows-service.md)

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

# eBPF 增强版本（需要额外依赖，见 docs/cargo-features.md）
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

## 📚 文档索引

各功能的详细介绍和配置说明拆分在 `docs/` 目录下的独立文档中：

| 文档 | 内容 |
| ---- | ---- |
| [命令行参数](docs/cli-options.md) | 全部命令行参数说明 |
| [TLS/SSL 配置](docs/tls.md) | 证书生成与配置、`--over-tls` TLS 加密代理 |
| [HTTPS MITM](docs/mitm.md) | MITM 配置、管理面板与实时明文查看、Stub 响应 |
| [静态文件托管](docs/static-file-serving.md) | 静态资源托管、Basic 认证、缓存控制、基于域名和路径的高级配置 |
| [反向代理](docs/reverse-proxy.md) | 反向代理规则、upstream 配置项、GitHub 资源代理、快捷反向代理 |
| [可观测性与监控](docs/observability.md) | Prometheus metrics、Grafana 大盘、实时网速监控 |
| [Cargo Features](docs/cargo-features.md) | eBPF 增强、jemalloc、aws-lc-rs 编译特性 |
| [高匿代理实现](docs/elite-proxy.md) | 代理特征清除与抓包验证 |
| [Windows 服务模式](docs/windows-service.md) | Windows 服务的编译、安装与管理 |
| [容器化开发](docs/container-dev.md) | 本地构建与测试容器镜像 |
| [客户端推荐](docs/clients.md) | 兼容的代理客户端 |
| [RPM 打包](RPM打包.md) | RPM 打包说明 |

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
