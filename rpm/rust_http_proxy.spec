Name:           rust_http_proxy
Version:        0.1
Release:        4.all
Summary:        Rust Http Proxy

License:        Apache License 2.0
URL:            https://github.com/arloor/rust_http_proxy
#Source0:

buildroot:      %_topdir/BUILDROOT
BuildRequires:  git
#Requires:

%description
Rust Http Proxy which is based on hyper and Tls-Listener.

%prep
if [ -d /tmp/rust_http_proxy ]; then
        cd /tmp/rust_http_proxy;
        git pull;
fi
if [ ! -d /tmp/rust_http_proxy ]; then
        git clone %{URL} /tmp/rust_http_proxy
fi

%build
cd /tmp/rust_http_proxy
cargo install --path . --target x86_64-unknown-linux-musl

%install
cd /tmp/rust_http_proxy
mkdir -p %{buildroot}/usr/bin
mkdir -p %{buildroot}/lib/systemd/system
mkdir -p %{buildroot}/etc/rust_http_proxy
install  -m755 target/x86_64-unknown-linux-musl/release/rust_http_proxy %{buildroot}/usr/bin/rust_http_proxy
install  -m755 rpm/rust_http_proxy.service %{buildroot}/lib/systemd/system/rust_http_proxy.service
install  -m755 rpm/env %{buildroot}/etc/rust_http_proxy/env

%check

%pre


%post
[ ! -d /usr/share/rust_http_proxy ]&&{
  mkdir -p /usr/share/rust_http_proxy
}
[ ! -f /usr/share/rust_http_proxy/privkey.pem ]&&{
  openssl req -x509 -newkey rsa:4096 -sha256 -nodes -keyout /usr/share/rust_http_proxy/privkey.pem -out /usr/share/rust_http_proxy/cert.pem -days 3650 -subj "/C=/ST=/L=/O=/OU=/CN=example.com"
}
systemctl daemon-reload

%files
/usr/bin/rust_http_proxy
%config /lib/systemd/system/rust_http_proxy.service
%config(noreplace) /etc/rust_http_proxy/env



%changelog
* Sun May 07 2023 root
- init