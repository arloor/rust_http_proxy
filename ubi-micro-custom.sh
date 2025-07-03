#! /bin/bash
# https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/html-single/building_running_and_managing_containers/index#proc_using-the-ubi-micro-images_assembly_adding-software-to-a-ubi-container

base_image=docker.io/redhat/ubi10-micro:latest
# base_image=docker.io/rockylinux/rockylinux:9-ubi-micro
out_tag=latest
out_image="docker.io/arloor/ubi-micro:${out_tag}"

yum install -y container-tools
microcontainer=$(buildah from ${base_image})
micromount=$(buildah mount $microcontainer)

# 从宿主机拷贝所有的zoneinfo到容器中
cp /usr/share/zoneinfo $micromount/usr/share/zoneinfo -r
# 设置时区为上海
cp /usr/share/zoneinfo/Asia/Shanghai $micromount/etc/localtime
echo "Asia/Shanghai" > $micromount/etc/timezone

# 安装所需的包
dnf install \
--installroot $micromount \
--releasever=10 \
--config /etc/dnf/dnf.conf \
--setopt install_weak_deps=false \
--setopt=reposdir=/etc/yum.repos.d/ \
--nodocs -y \
ca-certificates iproute zlib elfutils-libelf
dnf clean all --installroot $micromount

buildah umount $microcontainer
buildah commit $microcontainer ${out_image}
podman run --rm -it --network host ${out_image} ss;date

podman login docker.io
podman push ${out_image}
buildah rm -a
buildah prune -a 2>/dev/null