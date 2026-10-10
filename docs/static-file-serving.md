# 静态文件托管

`rust_http_proxy` 提供类 Nginx 的静态资源托管能力：

- **压缩支持**：自动 gzip 压缩，减少传输流量
- **断点续传**：支持 Accept-Ranges 和断点续传（单 range）
- **防盗链**：基于 Referer 请求头的图片防盗链功能（`--referer-keywords-to-self`）
- **网段白名单**：通过 `--allow-serving-network` 限制允许访问静态文件的 CIDR 网段

## 全局配置

通过 `--web-content-path` 参数指定默认静态资源目录：

```bash
rust_http_proxy -p 7788 --web-content-path /var/www/html
```

## 静态资源路径 Basic 认证

使用 `--static-auth-users` 指定静态资源专用账号。命令行参数只作用于 `--web-content-path` 生成的默认静态托管 location；如果不指定 `--static-auth-path-prefix`，会保护整个默认静态目录：

```bash
rust_http_proxy -p 7788 \
  --web-content-path /var/www/html \
  --static-auth-users alice:alice_password \
  --static-auth-users bob:bob_password
```

也可以使用 `--static-auth-path-prefix` 只保护部分 URL 路径前缀：

```bash
rust_http_proxy -p 7788 \
  --web-content-path /var/www/html \
  --static-auth-path-prefix /private \
  --static-auth-path-prefix /downloads/secret \
  --static-auth-users alice:alice_password \
  --static-auth-users bob:bob_password
```

浏览器访问受保护前缀时会自动弹出 Basic 认证框。`--static-auth-users` 与正向代理、`/metrics` 等使用的 `--users` 相互独立。

认证用户必须包含非空用户名和密码；密码可包含冒号。任意用户格式错误都会导致启动失败，不会被忽略。认证前缀可使用普通文本或百分号编码，但不接受空前缀、`.`/`..` 路径段或歧义分隔符。

## 路径与文件边界

路由前会解码 URL 路径中百分号编码的非保留字符，例如 `/%70rivate` 按 `/private` 路由和认证。`.`/`..` 路径段、重复斜线、反斜线、编码后的斜线/反斜线、嵌套百分号编码以及无效编码会被拒绝。正常的空格和 UTF-8 中文文件名仍可使用百分号编码访问。

Windows 上静态 location 和认证前缀忽略大小写；路径段末尾的点或空格、冒号及含 `~` 的文件名会被拒绝，以防文件系统别名、备用数据流或 8.3 短文件名绕过认证。所有层级的 `.git` 目录都禁止访问。文件和目录索引解析符号链接或 junction 后必须仍在托管根目录内。托管目录树不应允许不受信任的用户在请求处理期间修改。

空文件 GET 返回 `200` 和空正文，HEAD 返回 `Content-Length: 0`；空文件的 Range 请求返回 `416` 和 `Content-Range: bytes */0`。

## 静态资源缓存控制（Cache-Control）

静态资源响应会按路径是否受 Basic 认证保护自动设置 `Cache-Control`：

- 未被保护的路径：返回 `Cache-Control: public, max-age=<SECONDS>`，TTL 由 `--static-cache-max-age` 控制（默认 600 秒），便于浏览器和前置 CDN 缓存公开资源；
- 被认证保护的路径：始终返回 `Cache-Control: private, no-store`，防止认证后的内容被 CDN 等共享缓存存储并对匿名用户泄露。

`304 Not Modified` 响应同样携带对应的 `Cache-Control`。该行为对 `--location-config-file` 中配置了 `basic_auth_users`/`basic_auth_path_prefixes` 的静态托管 location 同样生效。

## 高级配置（基于域名和路径）

使用 `--location-config-file` 指定 YAML 配置文件，支持按域名、路径分别配置：

静态托管 location 中的 `basic_auth_users` 和 `basic_auth_path_prefixes` 都是可选字段。配置 `basic_auth_users` 但不配置 `basic_auth_path_prefixes` 时，会保护整个 location；配置 `basic_auth_path_prefixes` 时，仅保护这些相对当前 location 的路径前缀。`basic_auth_path_prefixes` 需要配合 `basic_auth_users` 使用。

```yaml
# 针对特定域名的配置
example.com:
  - location: / # URL 路径前缀，默认 /
    static_dir: /usr/share/nginx/html # 静态资源目录
  - location: /private/
    static_dir: /srv/private
    basic_auth_users: # 可选；不配置 basic_auth_path_prefixes 时保护整个 /private/ location
      - alice:alice_password
      - bob:bob_password

# 对所有域名生效的配置
default_host:
  - location: /static/
    static_dir: /var/www/static
  - location: /downloads/
    static_dir: /var/www/downloads
    basic_auth_users: # 可选
      - download:download_password
    basic_auth_path_prefixes: # 可选；相对当前 location，仅保护 /downloads/secret 和 /downloads/internal
      - /secret
      - /internal
```

同一个 `--location-config-file` 也可以配置反向代理规则，详见[反向代理](reverse-proxy.md)。
