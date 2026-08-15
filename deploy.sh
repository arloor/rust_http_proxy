#!/usr/bin/env bash
set -Eeuo pipefail

readonly PROJECT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly TARGET_TRIPLE="x86_64-unknown-linux-gnu"
readonly TARGET_PATH="/${TARGET_TRIPLE}"
readonly BINARY_PATH="${PROJECT_DIR}/target${TARGET_PATH}/release/rust_http_proxy"
readonly IMAGE="quay.io/arloor/rust_http_proxy:custom"
readonly REQUIRED_ZIG_VERSION="0.15.2"

usage() {
    cat <<'EOF'
用法: ./deploy.sh [选项]

选项:
  --skip-compile  跳过 Rust 二进制编译，复用已有构建产物
  --skip-image    跳过 Podman 镜像构建、登录和推送
  --skip-build    同时跳过二进制编译和镜像构建推送
  -h, --help      显示帮助信息
EOF
}

skip_compile=false
skip_image=false
while (($# > 0)); do
    case "$1" in
    --skip-compile)
        skip_compile=true
        ;;
    --skip-image)
        skip_image=true
        ;;
    --skip-build)
        skip_compile=true
        skip_image=true
        ;;
    -h | --help)
        usage
        exit 0
        ;;
    *)
        echo "未知参数: $1" >&2
        usage >&2
        exit 2
        ;;
    esac
    shift
done

cd "${PROJECT_DIR}"

required_commands=(kubectl ssh)
if [[ "${skip_compile}" == false ]]; then
    required_commands+=(cargo cargo-zigbuild install node npm zig)
fi
if [[ "${skip_compile}" == false || "${skip_image}" == false ]]; then
    required_commands+=(readelf)
fi
if [[ "${skip_image}" == false ]]; then
    required_commands+=(podman)
fi

for command_name in "${required_commands[@]}"; do
    if ! command -v "${command_name}" >/dev/null 2>&1; then
        echo "缺少部署依赖命令: ${command_name}" >&2
        exit 1
    fi
done

if [[ "${skip_compile}" == false && "$(zig version)" != "${REQUIRED_ZIG_VERSION}" ]]; then
    echo "Zig 版本必须为 ${REQUIRED_ZIG_VERSION}（当前为 $(zig version)）" >&2
    exit 1
fi

if [[ "${skip_compile}" == false ]]; then
    (
        cd "${PROJECT_DIR}/mitm-ui"
        npm ci
        npm test
        npm run build
    )

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
else
    echo "跳过 Rust 二进制编译"
fi

if [[ "${skip_compile}" == false || "${skip_image}" == false ]]; then
    if [[ ! -x "${BINARY_PATH}" ]]; then
        echo "未找到可用的构建产物: ${BINARY_PATH}" >&2
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
fi

if [[ "${skip_image}" == false ]]; then
    podman build . \
        -f Dockerfile.dyn \
        -t "${IMAGE}" \
        --network host \
        --build-arg "TARGET_PATH=${TARGET_PATH}"
    podman login quay.io
    podman push "${IMAGE}"
else
    echo "跳过 Podman 镜像构建、登录和推送"
fi

kubectl rollout restart ds/proxy
kubectl rollout status ds/proxy

hosts=(
    bwg.arloor.dev
    ttl.arloor.com
    us.arloor.dev
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
