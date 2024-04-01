#! /bin/bash
# 从ubi-micro镜像构建一个只有net-tools的镜像
# https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/html-single/building_running_and_managing_containers/index#proc_using-the-ubi-micro-images_assembly_adding-software-to-a-ubi-container

yum install -y container-tools
microcontainer=$(buildah from docker.io/rockylinux/rockylinux:9-ubi-micro)
micromount=$(buildah mount $microcontainer)
dnf install \
--installroot $micromount \
--releasever=9 \
--config /etc/dnf/dnf.conf \
--setopt install_weak_deps=false \
--setopt=reposdir=/etc/yum.repos.d/ \
--nodocs -y \
gawk net-tools 
dnf clean all \
--installroot $micromount
buildah umount $microcontainer
buildah commit $microcontainer docker.io/arloor/ubi-micro-net-tools:latest
podman run --rm -it --network host docker.io/arloor/ubi-micro-net-tools:latest /bin/sh
podman login docker.io
podman push docker.io/arloor/ubi-micro-net-tools:latest