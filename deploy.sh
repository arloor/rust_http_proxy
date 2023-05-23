ssh root@hk.arloor.dev "curl https://raw.githubusercontent.com/arloor/rust_http_proxy/master/rpm/genbin.sh -k |zsh"
scp root@hk.arloor.dev:/usr/bin/rust_http_proxy ~/Downloads/rust_http_proxy
scp root@hk.arloor.dev:/root/rpmbuild/RPMS/x86_64/rust_http_proxy-0.1-1.all.x86_64.rpm ~/Downloads/rust_http_proxy-0.1-1.all.x86_64.rpm
