cargo build -r --features aws_lc_rs,bpf,mimalloc --no-default-features
podman build . -f Dockerfile.dyn -t quay.io/arloor/rust_http_proxy:bpf --network host --env TARGET_PATH=
podman login quay.io
podman push quay.io/arloor/rust_http_proxy:bpf

#! /bin/bash
hosts="hk.arloor.dev us.arloor.dev bwg.arloor.dev ttl.arloor.com xq.arloor.com ti.arloor.com"
for i in ${hosts}; do
    ssh -o StrictHostKeyChecking=no root@${i} <<'EOFEOF'
        . pass
        hostname;
        systemctl restart proxy;
        podman rmi -a 2>/dev/null
        podman images --digests |grep arloor/rust_http_proxy|awk "{print \$4\" \"\$3}";
EOFEOF
done
