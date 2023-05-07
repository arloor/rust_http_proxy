Name:           rust_http_proxy
Version:        0.1
Release:        1%{?dist}
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
systemctl daemon-reload

%files
/usr/bin/rust_http_proxy
/lib/systemd/system/rust_http_proxy.service
/etc/rust_http_proxy/env



%changelog
* Sun May 07 2023 root
- init