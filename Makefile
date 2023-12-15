all: prepare install update

update: build
	bash deploy/update_github.sh


install: build
	bash deploy/install.sh

build:
	bash deploy/build.sh

prepare: rustup
	bash deploy/rpm_prepare.sh

rustup:
	bash deploy/rust_install.sh