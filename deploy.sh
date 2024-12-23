#! /bin/bash
hosts="hk.arloor.dev sg.arloor.dev us.arloor.dev bwg.arloor.dev hi.arloor.dev tt.arloor.com pl.arloor.com xq.arloor.com ti.arloor.com"
for i in ${hosts}; do
    ssh -o StrictHostKeyChecking=no root@${i} '
            hostname;
            systemctl restart proxy;
            podman rmi -a 2>/dev/null
            podman images --digests |grep arloor/rust_http_proxy|awk "{print \$4\" \"\$3}";
            '
done
