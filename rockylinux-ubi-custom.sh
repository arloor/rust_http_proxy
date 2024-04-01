#! /bin/bash
# 从ubi-micro镜像构建一个只有net-tools的镜像

yum install -y container-tools
microcontainer=$(buildah from docker.io/rockylinux/rockylinux:9-ubi-micro)
micromount=$(buildah mount $microcontainer)
dnf install \
--installroot $micromount \
--releasever=9 \
--setopt install_weak_deps=false \
--setopt=reposdir=/etc/yum.repos.d/ \
--nodocs -y \
net-tools
dnf clean all \
--installroot $micromount
buildah umount $microcontainer
buildah commit $microcontainer docker.io/arloor/ubi-micro-net-tools:latest
podman run --rm -it --network host docker.io/arloor/ubi-micro-net-tools:latest netstat -tulnp
podman login docker.io
podman push docker.io/arloor/ubi-micro-net-tools:latest