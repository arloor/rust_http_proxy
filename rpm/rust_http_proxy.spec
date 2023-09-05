Name:           rust_http_proxy
Version:        0.1
Release:        1.all
Summary:        Rust Http Proxy

License:        Apache License 2.0
URL:            https://github.com/arloor/rust_http_proxy
#Source0:

buildroot:      %_topdir/BUILDROOT
BuildRequires:  git
#Requires:

%description
Rust Http Proxy which is based on hyper、 Rustls and tokio.

%prep
echo "preparing"

%build
cd /var/rust_http_proxy
cargo install --path . --target x86_64-unknown-linux-musl

%install
cd /var/rust_http_proxy
mkdir -p %{buildroot}/usr/bin
mkdir -p %{buildroot}/lib/systemd/system
mkdir -p %{buildroot}/etc/rust_http_proxy
install  -m755 target/x86_64-unknown-linux-musl/release/rust_http_proxy %{buildroot}/usr/bin/rust_http_proxy
install  -m755 rpm/rust_http_proxy.service %{buildroot}/lib/systemd/system/rust_http_proxy.service
install  -m755 rpm/env %{buildroot}/etc/rust_http_proxy/env

%check

%pre


%post
# 处理%config(noreplace)类型的.rpmsave文件
[ -f /etc/rust_http_proxy/env.rpmsave ]&&{
  echo "恢复历史配置文件..."
  mv /etc/rust_http_proxy/env.rpmsave /etc/rust_http_proxy/env
}
[ ! -d /usr/share/rust_http_proxy ]&&{
  mkdir -p /usr/share/rust_http_proxy
}
[ ! -f /usr/share/rust_http_proxy/privkey.pem -o ! -f /usr/share/rust_http_proxy/cert.pem ]&&{
  if [ -f /usr/share/rust_http_proxy/cert.pem ]; then
    rm -f /usr/share/rust_http_proxy/cert.pem
  fi
  if [ -f /usr/share/rust_http_proxy/privkey.pem ]; then
      rm -f /usr/share/rust_http_proxy/privkey.pem
  fi
  echo "创建自签发ssl证书...."
  openssl req -x509 -newkey rsa:4096 -sha256 -nodes -keyout /usr/share/rust_http_proxy/privkey.pem -out /usr/share/rust_http_proxy/cert.pem -days 3650 -subj "/C=cn/ST=hl/L=sd/O=op/OU=as/CN=example.com"
}
echo "创建相关命令：/usr/local/bin/mo /usr/local/bin/lo"
cat > /usr/local/bin/mo <<\EOF
top -p `ps -ef|grep rust_http_proxy|grep -v grep|awk '{print $2}'|paste -sd ","`
EOF
chmod +x /usr/local/bin/mo
source /etc/rust_http_proxy/env
echo "tail -f -n 50 ${log_dir:-/tmp}/${log_file:-proxy.log}" > /usr/local/bin/lo
chmod +x /usr/local/bin/lo

systemctl daemon-reload

%files
/usr/bin/rust_http_proxy
%config /lib/systemd/system/rust_http_proxy.service
%config(noreplace) /etc/rust_http_proxy/env



%changelog
* Sun May 07 2023 root
- init