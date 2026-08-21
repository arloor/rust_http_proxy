# 反向代理

`rust_http_proxy` 支持灵活配置反向代理路由规则，正向代理和反向代理均支持 websocket。

## 基于配置文件的反向代理

使用 `--location-config-file` 配置反向代理规则：

```yaml
# 针对特定域名
api.example.com:
  - location: /api
    basic_auth_users: # 可选；不配置 basic_auth_path_prefixes 时保护整个 /api
      - alice:alice_password
    basic_auth_path_prefixes: # 可选；相对当前 location 的路径前缀
      - /private
    upstream:
      url_base: "https://backend.internal.com/api/" # 上游 scheme 和路径
      connect_to: "10.0.0.8:8443" # 可选：DNS/TCP 连接目标
      tls_server_name: "backend.internal.com" # 可选：TLS SNI 和证书校验名
      authority: "#{host}" # 可选：H1 Host / H2 :authority
      version: "AUTO" # HTTP 版本: H1/H2/AUTO
      headers: # 可选：修改发送给上游的请求头
        X-Custom-Header: "custom_value"
```

反向代理 location 的 `basic_auth_users` 和 `basic_auth_path_prefixes` 语义与[静态文件托管](static-file-serving.md)一致。认证使用客户端请求的 `Authorization: Basic ...`；对于命中受保护路径的请求，该请求头在认证后会被移除，不会透传给 upstream。未启用认证或未命中受保护路径时，保持原有请求头透传行为。

反向代理到上游的请求url构建方式如下：

```rust
let remaining = path_and_query.get(location.len()..).ok_or("location 不匹配请求路径")?;
let upstream_url = upstream.url_base.clone() + remaining;
```

## upstream 配置项说明

| 参数              | 说明                                                | 默认值/可选值                            |
| ----------------- | --------------------------------------------------- | ---------------------------------------- |
| `url_base`        | 上游 scheme、默认主机与基础路径                     | 任意有效 URL                             |
| `connect_to`      | DNS/TCP 实际连接目标；必须是静态域名或 IP           | `url_base` 的 authority（自动补 80/443） |
| `tls_server_name` | TLS SNI 与证书校验名；必须是静态 DNS 名或 IP        | `url_base` 的 host                       |
| `authority`       | HTTP 虚拟主机：H1 写入 `Host`，H2 写入 `:authority` | `url_base` 的 authority，支持 `#{host}`  |
| `version`         | HTTP 协议版本                                       | `H1`、`H2`、`AUTO`（默认）               |
| `headers`         | 覆盖/添加发送给上游的请求头                         | 键值对，支持 `#{host}`                   |

`H1` 和 `H2` 使用彼此独立且严格限定协议的客户端。HTTPS upstream 的 `AUTO` 沿用入口请求版本后再分流，明文 HTTP upstream 则使用 H1；若对 `http://` upstream 显式指定 `H2`，使用的是 h2c prior knowledge，上游必须直接接受明文 HTTP/2。H2 不发送普通 `Host`，但会把 `authority` 写入 `:authority`，因此仍支持独立于连接目标和 TLS SNI 的虚拟主机。为兼容旧配置，未设置 `authority` 时，`headers.Host` 会作为 authority 使用。

`connect_to` 和 `tls_server_name` 不接受 `#{host}`，避免外部请求的 Host 控制代理的 DNS/TCP 或 TLS 目标。需要动态虚拟主机时只配置 `authority: "#{host}"`（或兼容写法 `headers.Host: "#{host}"`）；连接目标与证书校验名应保持静态。
`#{host}` 会保留原请求的非默认端口，但会省略与原请求 scheme 匹配的默认端口（HTTP 的 80、HTTPS 的 443）。H2 使用解析后的值生成 `:authority`，不会额外发送普通 `Host` 请求头。

## 内置反向代理功能

### GitHub 资源代理

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

### 快捷反向代理

通过 `--append-upstream-url` 快速配置反向代理：

```bash
rust_http_proxy -p 7788 --append-upstream-url=https://cdnjs.cloudflare.com
```

访问方式：

```
https://YOUR_DOMAIN/https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js
```

等价于以下 YAML 配置：

```yaml
default_host:
  - location: /https://cdnjs.cloudflare.com
    upstream:
      url_base: https://cdnjs.cloudflare.com
      version: AUTO
```
