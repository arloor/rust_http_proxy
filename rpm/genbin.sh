## 打包
if [ -d /var/rust_http_proxy ]; then
  cd /var/rust_http_proxy
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


## 安装
version=0.1
release=1.all
systemctl stop rust_http_proxy
yum remove -y rust_http_proxy
# rpm -ivh在安装新版本时会报错文件冲突，原因是他没有进行更新或降级的能力，而yum install可以处理可执行文件的更新或降级
yum install -y ~/rpmbuild/RPMS/x86_64/rust_http_proxy-${version}-${release}.x86_64.rpm

## 启动
systemctl daemon-reload
systemctl start rust_http_proxy
systemctl status rust_http_proxy --no-page

python update_release.py
