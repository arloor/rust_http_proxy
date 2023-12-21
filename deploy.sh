#! /bin/bash
hosts="hk.arloor.dev sg.arloor.dev di.arloor.dev us.arloor.dev gg.arloor.dev ti.arloor.dev"
for i in ${hosts};
do
    ssh root@${i} 'source /etc/profile;hostname;systemctl restart proxy;podman rmi -a 2>/dev/null'
done

ssh root@us.arloor.dev 'source /etc/profile;hostname;systemctl restart guest;podman rmi -a 2>/dev/null'