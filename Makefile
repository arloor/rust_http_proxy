all: install update

update: build
	bash deploy/update_github.sh


install: build
	bash deploy/install.sh

build:
	bash deploy/build.sh

# 第一次执行需要 make pre&&make all
pre: rust musl
	bash deploy/rpm_prepare.sh

rust:
	bash deploy/rust_install.sh

musl:
	bash deploy/musl.sh

gh:
	cargo install --path .
	gh release delete-asset v1.0.0 rust_http_proxy --repo github.com/arloor/rust_http_proxy -y
	gh release upload v1.0.0 target/release/rust_http_proxy --repo github.com/arloor/rust_http_proxy