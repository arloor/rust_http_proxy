#! /bin/bash
hosts="ti.arloor.dev hk.arloor.dev sg.arloor.dev di.arloor.dev us.arloor.dev gg.arloor.dev bwg.arloor.dev"
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
            podman rmi -a 2>/dev/null
            '
done
ssh -o StrictHostKeyChecking=no root@us.arloor.dev '
            source /etc/profile
            echo $http_proxy
            hostname;
            systemctl restart guest;
            podman rmi -a 2>/dev/null
            '
