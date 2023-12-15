all: prepare rustup build install

install: build
	@source /etc/profile;\
	version=0.1 && release=1.all; \
	systemctl stop rust_http_proxy; \
	yum remove -y rust_http_proxy; \
	yum install -y ~/rpmbuild/RPMS/x86_64/rust_http_proxy-0.1-1.all.x86_64.rpm;\
	systemctl daemon-reload&&systemctl start rust_http_proxy
	. /etc/profile.d/github.sh && python /var/rust_http_proxy/update_release.py

build:
	rpmbuild -bb ./rpm/rust_http_proxy.spec

prepare:
	yum install -y rpm-build rpmdevtools
	rpmdev-setuptree

rustup:
	curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- --default-host x86_64-unknown-linux-gnu -y
	@source /etc/profile; \
	cd /var/; \
	wget http://musl.libc.org/releases/musl-1.2.3.tar.gz -O musl-1.2.3.tar.gz; \
	yum install -y gcc make; \
	tar -zxvf musl-1.2.3.tar.gz; \
	cd musl-1.2.3; \
	./configure && make -j 2 && make install; \
	ln -fs /usr/local/musl/bin/musl-gcc /usr/local/bin/musl-gcc; \
	rustup target add x86_64-unknown-linux-musl