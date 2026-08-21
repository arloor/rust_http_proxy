# 容器化开发

## 本地测试

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

eBPF 增强版本的编译依赖见 [Cargo Features](cargo-features.md#-ebpf-增强推荐)。
