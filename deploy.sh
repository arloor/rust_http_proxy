scp root@hk.arloor.dev:/root/.acme.sh/arloor.dev/fullchain.cer cert.pem
scp root@hk.arloor.dev:/root/.acme.sh/arloor.dev/arloor.dev.key privkey.pem
ssh root@hk.arloor.dev "curl https://raw.githubusercontent.com/arloor/rust_http_proxy/master/rpm/genbin.sh -k 2>/dev/null |zsh"
scp root@hk.arloor.dev:/usr/bin/rust_http_proxy ~/Downloads/rust_http_proxy
scp root@hk.arloor.dev:/root/rpmbuild/RPMS/x86_64/rust_http_proxy-0.1-1.all.x86_64.rpm ~/Downloads/rust_http_proxy-0.1-1.all.x86_64.rpm

for i in arloor.com sg.arloor.dev dc6.arloor.dev dc9.arloor.dev bwg.arloor.dev; do
  ssh root@${i} "
      curl -k https://hk.arloor.dev:444/rust_http_proxy-0.1-1.all.x86_64.rpm -o /tmp/rust_http_proxy-0.1-1.all.x86_64.rpm
      systemctl stop rust_http_proxy
      yum remove -y rust_http_proxy
      # rpm -ivh在安装新版本时会报错文件冲突，原因是他没有进行更新或降级的能力，而yum install可以处理可执行文件的更新或降级
      yum install -y /tmp/rust_http_proxy-0.1-1.all.x86_64.rpm

      ## 启动
      systemctl daemon-reload
      systemctl start rust_http_proxy
      sleep 3
      tail -n  10 /data/var/log/proxy/proxy.log
    "
done
