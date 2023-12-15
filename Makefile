all: update

update: build
	bash deploy/update_github.sh


install: build
	bash deploy/install.sh

build:
	bash deploy/build.sh

# 第一次执行需要 make pre&&make all
pre: rustup
	bash deploy/rpm_prepare.sh

rustup:
	bash deploy/rust_install.sh