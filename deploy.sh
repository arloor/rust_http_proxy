ssh root@mi.arloor.com -t "curl https://raw.githubusercontent.com/arloor/rust_http_proxy/master/rpm/genbin.sh -k 2>/dev/null |zsh"
scp root@mi.arloor.com:/usr/bin/rust_http_proxy ~/Downloads/rust_http_proxy
scp root@mi.arloor.com:/root/rpmbuild/RPMS/x86_64/rust_http_proxy-0.1-1.all.x86_64.rpm ~/Downloads/rust_http_proxy-0.1-1.all.x86_64.rpm

#for i in bwg.arloor.dev mi.arloor.com ti.arloor.com ; do
#  ssh root@${i} "
#      curl -k https://mi.arloor.com:443/rust_http_proxy-0.1-1.all.x86_64.rpm -o /tmp/rust_http_proxy-0.1-1.all.x86_64.rpm
#      yum remove -y rust_http_proxy
#      ps -ef|grep rust_http_proxy|grep -v grep
#      # rpm -ivh在安装新版本时会报错文件冲突，原因是他没有进行更新或降级的能力，而yum install可以处理可执行文件的更新或降级
#      yum install -y /tmp/rust_http_proxy-0.1-1.all.x86_64.rpm
#      systemctl daemon-reload
#      systemctl restart rust_http_proxy
#    "
#done
