ssh root@pi.arloor.com 'bash /var/rust_http_proxy/rpm/genbin.sh'
scp root@pi.arloor.com:/usr/bin/rust_http_proxy ~/Downloads
scp root@pi.arloor.com:/root/rpmbuild/RPMS/x86_64/rust_http_proxy-0.1-1.all.x86_64.rpm ~/Downloads
ls -l ~/Downloads/rust_http_proxy*
