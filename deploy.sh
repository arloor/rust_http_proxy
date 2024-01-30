#! /bin/bash
hosts="hk.arloor.dev nf.arloor.dev sg.arloor.dev di.arloor.dev us.arloor.dev gg.arloor.dev ti.arloor.com"
# echo "" > ~/.ssh/known_hosts
# for i in ${hosts}; do
#     ssh-keyscan -H ${i} >> ~/.ssh/known_hosts
# done
for i in ${hosts}; do
    ssh -o StrictHostKeyChecking=no root@${i} '
            hostname;
            systemctl restart proxy;
            podman image prune -f 2>/dev/null
            podman images |grep arloor/rust_http_proxy;
            '
done
