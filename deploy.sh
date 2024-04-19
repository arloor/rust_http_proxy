#! /bin/bash
hosts="gg.arloor.dev"
for i in ${hosts}; do
    ssh -o StrictHostKeyChecking=no root@${i} '
            hostname;
            systemctl restart proxy;
            podman image prune -f 2>/dev/null
            podman images --digests |grep arloor/rust_http_proxy|awk "{print \$4\" \"\$3}";
            '
done

hosts="hk.arloor.dev sg.arloor.dev di.arloor.dev us.arloor.dev bwg.arloor.dev pl.arloor.com ti.arloor.com li.arloor.dev"
for i in ${hosts}; do
    ssh -o StrictHostKeyChecking=no root@${i} '
            hostname;
            curl -SLf https://github.com/arloor/rust_http_proxy/releases/download/vebpf/rust_http_proxy -o /tmp/aasdasdada
            install /tmp/aasdasdada /usr/bin/rust_http_proxy&&rm -f /tmp/aasdasdada
            systemctl restart rust_http_proxy;
            '
done