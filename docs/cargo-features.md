# Cargo Features

本项目支持多种编译特性，可根据需求选择。

## 🔥 eBPF 增强（推荐）

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

## 🧠 Jemalloc 内存分配器

在 Unix 平台使用 jemalloc 替代系统默认内存分配器，提供更好的并发性能和减少内存碎片。`jemalloc` feature 在非 Unix 平台不会启用 jemalloc；Windows 仍使用默认启用的 mimalloc。

**编译方式**：

```bash
cargo build --release --features jemalloc
```

**特点**：

- ✅ 更高的并发分配能力
- ✅ 减少内存碎片
- ⚠️ 会缓存更多内存，`top` 命令中 RES 值可能较高

## 🔐 AWS-LC-RS 加密后端

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
