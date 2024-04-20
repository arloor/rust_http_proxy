#! /bin/bash
# 从ubi-micro镜像构建一个只有net-tools的镜像
# https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/html-single/building_running_and_managing_containers/index#proc_using-the-ubi-micro-images_assembly_adding-software-to-a-ubi-container

# base_image="docker.io/redhat/ubi9-micro:latest"
base_image="docker.io/rockylinux/rockylinux:9-ubi-micro"
out_tag="latest"
out_image="docker.io/arloor/ubi-micro:${out_tag}"

yum install -y container-tools
microcontainer=$(buildah from ${base_image})
micromount=$(buildah mount $microcontainer)
dnf install \
--installroot $micromount \
--releasever=9 \
--config /etc/dnf/dnf.conf \
--setopt install_weak_deps=false \
--setopt=reposdir=/etc/yum.repos.d/ \
--nodocs -y \
gawk net-tools tzdata zlib-devel elfutils-libelf-devel
dnf clean all \
--installroot $micromount
buildah umount $microcontainer
buildah commit $microcontainer ${out_image}
podman run --rm -it --network host ${out_image} netstat -tulnp
podman run --rm -it --network host ${out_image} awk
podman run --rm -it --network host ${out_image} cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime&&echo "Asia/Shanghai" > /etc/timezone&&date
podman login docker.io
podman push ${out_image}
buildah rm -a
buildah prune -a 2>/dev/null