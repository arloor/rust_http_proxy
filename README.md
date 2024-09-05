[![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/arloor/rust_http_proxy)

基于 `hyper` 和 `rustls` 的静态资源托管服务器、正向代理、反向代理。支持以下特性：

1. 使用tls来对正向代理流量进行加密（`--over-tls`）。
2. 类Nginx的静态资源托管。支持gzip压缩。支持Accept-Ranges以支持断点续传（备注：暂不支持多range，例如 `Range: bytes=0-100,100-` ）
3. 支持反向代理（ `--reverse-proxy` ）。目前仅支持根据host路由到upstream的url，不支持其他匹配规则。
4. 基于Prometheus的可观测，可以监控代理的流量、外链访问等。
5. 采集网卡上行流量，展示在 `/speed` 路径下（读取 `/proc/net/dev` 或基于 `ebpf socket filter` ）
5. 支持多端口，多用户。
6. 每天定时加载tls证书，acme证书过期重新签发时不需要重启服务。
7. 连接空闲（10分钟没有IO）自动关闭。
8. 可选feature：jemalloc内存分配器。使用`cargo build --features jemalloc`命令编译以激活

提及的参数详见[命令行参数](#命令行参数)

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
           [default: ]
  -w, --web-content-path <WEB_CONTENT_PATH>
          [default: /usr/share/nginx/html]
  -r, --referer <REFERER>
          Http Referer请求头处理 
          1. 图片资源的防盗链：针对png/jpeg/jpg等文件的请求，要求Request的Referer header要么为空，要么配置的值
          2. 外链访问监控：如果Referer不包含配置的值，并且访问html资源时，Prometheus counter req_from_out++，用于外链访问监控
           [default: ]
      --never-ask-for-auth
          if enable, never send '407 Proxy Authentication Required' to client。
          不建议开启，否则有被嗅探的风险
          
  -o, --over-tls
          if enable, proxy server will listen on https
      --hostname <HOSTNAME>
          [default: unknown]
      --reverse-proxy <HOST=>URL[=>VERSION]>
          特定的HOST转发到特定的URL，并且使用特定的VERSION。
          其中URL必须包含scheme和host。
          其中VERSION可以填写HTTP11或者HTTP2，如果不填，则自动推断。一般来说，只在Https网站只支持http/1.1的时候，例如反代https://www.baidu.com，才需要显式设置为HTTP11，其他时候不需要设置。
          例如：--reverse-proxy=localhost:7788=>http://example.com # http(s)://localhost:7788转发到http://example.com
          例如：--reverse-proxy=localhost:7788=>https://example.com # http(s)://localhost:7788转发到https://example.com
          例如：--reverse-proxy=localhost:7788=>https://example.com=>HTTP11 # http(s)://localhost:7788转发到https://example.com，并且使用HTTP/1.1
          例如：--reverse-proxy=localhost:7788=>https://example.com/path/to/ # http(s)://localhost:7788/index.html转发到https://example.com/path/to/index.html
          
  -h, --help
          Print help
```

**SSL配置**

其中，tls证书(`--cert`)和pem格式的私钥(`--key`)可以通过openssl命令一键生成：

```shell
openssl req -x509 -newkey rsa:4096 -sha256 -nodes -keyout /usr/share/rust_http_proxy/privkey.pem -out /usr/share/rust_http_proxy/cert.pem -days 3650 -subj "/C=cn/ST=hl/L=sd/O=op/OU=as/CN=example.com"
```

如需签名证书，请购买tls证书或免费解决方案（acme.sh等）

**测试TLS Proxy**

可以使用curl （7.52.0以上版本）来测试

```shell
curl  https://ip.im/info --proxy-user "username:password" -x https://localhost:7788  --proxy-insecure
```

## 安装说明

### linux amd64 可执行文件

```shell
curl -SLf https://github.com/arloor/rust_http_proxy/releases/download/latest/rust_http_proxy -o /tmp/rust_http_proxy
mv /tmp/rust_http_proxy /usr/bin/rust_http_proxy&&chmod +x /usr/bin/rust_http_proxy
/usr/bin/rust_http_proxy -p 8888
```

### Docker 安装 

> 通过Github Action自动更新release，永远是最新版，可放心使用

```shell
docker run --rm -it --net host docker.io/arloor/rust_http_proxy -p 8888
```

### ebpf版本安装

> 注意：ebpf版本并没有什么新特性，只是为了学习下新技术的自嗨。

```bash
curl -SLf https://github.com/arloor/rust_http_proxy/releases/download/bpf/rust_http_proxy -o /tmp/rust_http_proxy
mv /tmp/rust_http_proxy /usr/bin/rust_http_proxy&&chmod +x /usr/bin/rust_http_proxy
/usr/bin/rust_http_proxy -p 8888
```

或者

```bash
docker run --rm -it --privileged --net host docker.io/arloor/rust_http_proxy:bpf -p 8888
```

## 可观测

### Linux运行时的网速监控

在linux运行时，会监控网卡网速，并展示在 `/speed` 。

![](speed.png)

### Prometheus Exporter

提供了Prometheus的Exporter。如果设置了`--users`参数，则需要在header中设置authorization，否则会返回`401 UNAUTHORIZED`。

```text
# HELP req_from_out Number of HTTP requests received.
# TYPE req_from_out counter
req_from_out_total{referer="all",path="all"} 4
# HELP proxy_traffic num proxy_traffic.
# TYPE proxy_traffic counter
# EOF
```

可以使用[此Grafana大盘Template](https://grafana.com/grafana/dashboards/20185-rust-http-proxy/)来创建Grafana大盘，效果如下

![alt text](grafana-template1.png)
![alt text](grafana-template2.png)

## 客户端

- Clash系列
    - [clash-verge-rev](https://github.com/clash-verge-rev/clash-verge-rev) 
    - [ClashMetaForAndroid](https://github.com/MetaCubeX/ClashMetaForAndroid)
    - [mihomo(clash-meta)](https://github.com/MetaCubeX/mihomo/tree/Meta) 
- 自研玩具
    - Rust：[sslocal(fork shadowsocks-rust)](https://github.com/arloor/shadowsocks-rust)
    - Golang：[forward](https://github.com/arloor/forward)
    - Java: [connect](https://github.com/arloor/connect)
        




## Cargo Features

### jemalloc

拥有更高的并发分配能力和减少内存碎片，不过会buffer更多的内存，因此top中RES数值会有上升。激活方式：

```bash
cargo build --features jemalloc
```

### aws_lc_rs

`aws_lc_rs` 和 `ring` 是 `rustls` 的两个加密后端。本项目默认使用 `ring` 作为加密后端，也可选择[aws_lc_rs](https://crates.io/crates/aws-lc-rs)作为加密后端。`aws_lc_rs` 相比ring主要有两点优势:

1. 在[rustls的benchmark测试](https://github.com/aochagavia/rustls-bench-results)中，`aws_lc_rs` 的性能要优于 `ring` 。
2. 支持美国联邦政府针对加密提出的[fips要求](https://csrc.nist.gov/pubs/fips/140-2/upd2/final)。

不过，使用 `aws_lc_rs` 会增加一些编译难度，需要额外做以下操作：

| 依赖的包 | 是否必须 |安装方式 |
| --- | --- | --- |
| `cmake` | 必须 | `apt-get install cmake` |
| `clang` | 非必需。仅在 `aws_lc_rs` 没有提供pre-generated bindings的target上需要，详见：[the requirements for rust-bindgen](https://rust-lang.github.io/rust-bindgen/requirements.html)。另外还需要激活 `aws-lc-rs/bindgen`（见备注）。 |`apt-get install clang` |

激活方式：

```bash
cargo build --no-default-features --features aws_lc_rs
```

**备注**：激活 `aws-lc-rs/bindgen`:

```toml
[target.'cfg(target_env = "musl")'.dependencies]
aws-lc-rs= { version = "1.6", features = ["bindgen"],optional = true }

[features]
# aws_lc_rs = ["tokio-rustls/aws-lc-rs"]
aws_lc_rs = ["tokio-rustls/aws-lc-rs","aws-lc-rs/bindgen"]
```

### bpf

使用ebpf来统计网卡出流量，仅在 `x86_64-unknown-linux-gnu` 上测试过。激活方式:

```bash
cargo build --features bpf
```

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
- ~~[rustls async Acceptor for hyper v1](https://github.com/Gelbpunkt/hyper-rustls/blob/3d88d7d76c2e91e39b028dbbb92db917aa051092/src/acceptor.rs)已删除~~ [Update hyper to 1.x and integrate with hyper-util #232](https://github.com/rustls/hyper-rustls/pull/232#issuecomment-1878924476)的PR中hyper-rustls已删除tls acceptor，因为无必要