#! /bin/bash
hosts="hk.arloor.dev hkg.arloor.dev sg.arloor.dev di.arloor.dev us.arloor.dev gg.arloor.dev bwg.arloor.dev ti.arloor.com li.arloor.com"
# echo "" > ~/.ssh/known_hosts
# for i in ${hosts}; do
#     ssh-keyscan -H ${i} >> ~/.ssh/known_hosts
# done
for i in ${hosts}; do
    ssh -o StrictHostKeyChecking=no root@${i} '
            source /etc/profile
            echo $http_proxy
            hostname;
            systemctl restart proxy;
            podman image prune -f 2>/dev/null
            '
done
