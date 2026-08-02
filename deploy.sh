#!/usr/bin/env bash
set -Eeuo pipefail

readonly PROJECT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly TARGET_TRIPLE="x86_64-unknown-linux-gnu"
readonly TARGET_PATH="/${TARGET_TRIPLE}"
readonly BINARY_PATH="${PROJECT_DIR}/target${TARGET_PATH}/release/rust_http_proxy"
readonly IMAGE="quay.io/arloor/rust_http_proxy:custom"
readonly REQUIRED_ZIG_VERSION="0.15.2"

cd "${PROJECT_DIR}"

for command_name in cargo cargo-zigbuild install kubectl podman readelf ssh zig; do
    if ! command -v "${command_name}" >/dev/null 2>&1; then
        echo "缺少部署依赖命令: ${command_name}" >&2
        exit 1
    fi
done

if [[ "$(zig version)" != "${REQUIRED_ZIG_VERSION}" ]]; then
    echo "Zig 版本必须为 ${REQUIRED_ZIG_VERSION}（当前为 $(zig version)）" >&2
    exit 1
fi

# 与 GitHub Actions 的 bpf-dyn-link 构建保持一致。cargo-zigbuild 会隐藏
# /usr/include，因此只把 libbpf 构建所需的第三方头文件放回搜索路径。
libbpf_zig_include="$(mktemp -d)"
trap 'rm -rf "${libbpf_zig_include}"' EXIT
install -m 0644 \
    /usr/include/libelf.h \
    /usr/include/gelf.h \
    /usr/include/zlib.h \
    /usr/include/zconf.h \
    "${libbpf_zig_include}/"
export LIBBPF_SYS_EXTRA_CFLAGS="-isystem ${libbpf_zig_include}"
export LIBBPF_SYS_LIBRARY_PATH=/usr/lib/x86_64-linux-gnu
# x86_64 的 off_t 本身就是 64 位；避免 libbpf 把 fcntl 重定向到
# GLIBC_2.28 才提供的 fcntl64，否则无法生成 glibc 2.17 兼容产物。
export CPPFLAGS=-U_FILE_OFFSET_BITS
export CARGO_TARGET_DIR="${PROJECT_DIR}/target"

cargo zigbuild --release \
    --target "${TARGET_TRIPLE}.2.17" \
    -p rust_http_proxy \
    --features bpf

if [[ ! -x "${BINARY_PATH}" ]]; then
    echo "未找到 zigbuild 产物: ${BINARY_PATH}" >&2
    exit 1
fi

max_glibc=$(
    readelf -W --version-info --dyn-syms "${BINARY_PATH}" |
        grep -oE 'GLIBC_[0-9]+(\.[0-9]+)+' |
        sed 's/^GLIBC_//' |
        sort -Vu |
        tail -n 1 || true
)
if [[ -z "${max_glibc}" ]] ||
    [[ "$(printf '%s\n' 2.17 "${max_glibc}" | sort -V | tail -n 1)" != "2.17" ]]; then
    echo "${BINARY_PATH} 需要 GLIBC_${max_glibc:-unknown}，预期最高为 GLIBC_2.17" >&2
    exit 1
fi

podman build . \
    -f Dockerfile.dyn \
    -t "${IMAGE}" \
    --network host \
    --build-arg "TARGET_PATH=${TARGET_PATH}"
podman login quay.io
podman push "${IMAGE}"

kubectl rollout restart ds/proxy
kubectl rollout status ds/proxy

hosts=(
    ttl.arloor.com
    us.arloor.dev
    bwg.arloor.dev
    hk.arloor.dev
    ti.arloor.dev
    bj.arloor.com
    sh.arloor.com
)
for host in "${hosts[@]}"; do
    ssh -o StrictHostKeyChecking=no "root@${host}" 'bash -se' <<'EOFEOF'
. pass | true
hostname
systemctl restart proxy
podman rmi -a 2>/dev/null || true
podman images --digests | awk '/arloor\/rust_http_proxy/ {print $4, $3}'
EOFEOF
done
