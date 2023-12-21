all: gh


rpm:
	bash deploy/rpm.sh

# 第一次执行需要 make pre&&make all
pre: rust musl
	bash deploy/rpm_prepare.sh

rust:
	bash deploy/rust_install.sh

musl:
	bash deploy/musl.sh

gh:
	cargo install --path .
	if [ -f /etc/os-release ]; \
	then \
		cp target/release/rust_http_proxy target/release/rust_http_proxy_linux; \
		gh release delete-asset v1.0.0 rust_http_proxy_linux -y; \
		gh release upload v1.0.0 target/release/rust_http_proxy_linux; \
	else \
		cp target/release/rust_http_proxy target/release/rust_http_proxy_mac; \
		gh release delete-asset v1.0.0 rust_http_proxy_mac -y; \
		gh release upload v1.0.0 target/release/rust_http_proxy_mac; \
	fi