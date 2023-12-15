if [ -d /var/rust_http_proxy ]; then
        cd /var/rust_http_proxy;
          git pull --ff-only || {
            echo "git pull 失败，重新clone"
            cd /var
            rm -rf /var/rust_http_proxy
            git clone https://github.com/arloor/rust_http_proxy /var/rust_http_proxy
          }
else
        git clone https://github.com/arloor/rust_http_proxy /var/rust_http_proxy
fi
rpmbuild -bb /var/rust_http_proxy/rpm/rust_http_proxy.spec