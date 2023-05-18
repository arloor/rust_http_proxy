## RPM打包流程

### 安装rpm工具包

```shell
yum install -y rpm-build
yum install -y rpmdevtools
```

### 创建工作空间

rpmdev-setuptree是rpmdevtools中带的初始化环境脚本，执行后会在用户主目录下创建rpmbuild目录和.rpmmacros文件，同时生成所需的子目录和默认的控制参数，执行：

```shell
rpmdev-setuptree
```


自动生成的目录结构:

```shell
-- rpmbuild
|-- BUILD
|-- RPMS
|-- SOURCES
|-- SPECS
|-- SRPMS
```

### spec文件说明

`rust_http_proxy.spec`写的比较简单，没有使用内置宏或内置变量，适合我这种不熟悉rpm打包的人。总体思路就是能自己写的全部自己写，最终只用到了`%{buildroot}`这一个内置变量，用于控制将编译输出到哪里。
因为没有使用内置宏，所有每个阶段都尽可能使用了绝对路径，或者在一开始cd到目标目录中。下面介绍下具体过程：

- %prep: 使用git拉取代码
- %build：使用cargo编译代码
- %install: 将编译好的二进制文件和相关配置文件install到`%{buildroot}`中
- %files： 指定要将哪些文件打到rpm包中，其中%config被标记为配置文件，升级时会覆盖配置文件，noreplace则不会被覆盖配置文件
- %post： 用户安装该RPM后自动执行的操作。这里是触发`systemctl daemon-reload`，因为rpm包中有service文件

**Release没有带el8、el9标识的特别说明：**

因为rust静态链接的可执行文件在不同centos版本都可运行，所以不做区分，如果要改回去，可以使用`%{?dist}`宏

```text
Release:        3%{?dist}
```


### 开始打 RPM 包
rpmbuild命令会根据spec文件来生成rpm包，主要用到以下几个参数

```shell
rpmbuild  --help
-bp 执行到%prep阶段结束
-bc 执行到%build阶段结束
-bi 执行到%install阶段结束
-bl 检测%files文件是否有丢失
-ba 创建src.rpm和二进制包
-bs 只创建src.rpm源码包
-bb 只创建二进制rpm包
```

常用的参数就这几个，其它的自己看man手册，开始打包：

```shell
rpmbuild -bp motan-go.spec
rpmbuild -bc motan-go.spec
rpmbuild -bi motan-go.spec
rpmbuild -bl motan-go.spec
rpmbuild -ba motan-go.spec
```

分阶段测试,方便排错，如果哪个阶段有错误，可以使用–short-circuit跳过之前成功的阶段，节省时间

```shell
rpmbuild -bi --short-circuit  ngx_openresty.spec
```

### 安装RPM

```shell
rpm -ivh ~/rpmbuild/RPMS/x86_64/rust_http_proxy-${verion}.el9.x86_64.rpm #rpm包在此
```


### 增加change log

```shell
rpmdev-bumpspec --comment=$(date) --userstring=root  rpm/rust_http_proxy.spec
```

### 参考文档

- [新手RPM打包教程](https://www.jianshu.com/p/283768d15601)
- [CentOS 如何打 RPM 包](https://idevz.org/2017/07/centos-%E5%A6%82%E4%BD%95%E6%89%93-rpm-%E5%8C%85/)
- [第 1 章 RPM 打包入门](https://access.redhat.com/documentation/zh-cn/red_hat_enterprise_linux/8/html/packaging_and_distributing_software/getting-started-with-rpm-packaging_packaging-and-distributing-software)

## 具体shell命令


### 安装musl和Rust

安装rust和musl支持，以打包静态链接的可执行文件

```shell
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- --default-host x86_64-unknown-linux-gnu -y
source "$HOME/.cargo/env"
cd /var/
wget http://musl.libc.org/releases/musl-1.2.3.tar.gz -O musl-1.2.3.tar.gz
yum install -y gcc
tar -zxvf musl-1.2.3.tar.gz
cd musl-1.2.3
./configure
make -j 2
make install
ln -fs /usr/local/musl/bin/musl-gcc /usr/local/bin/musl-gcc
rustup target add x86_64-unknown-linux-musl
```

### rpmbuild的准备工作

```shell
## 打包
yum install -y rpm-build
yum install -y rpmdevtools
rm -rf ~/rpmbuild
rpmdev-setuptree
```

### 打包

```shell
wget https://raw.githubusercontent.com/arloor/rust_http_proxy/master/rpm/rust_http_proxy.spec -O /var/rust_http_proxy.spec
rpmbuild -bb /var/rust_http_proxy.spec
```

### 安装

```shell
## 安装
version=0.1
release=12.all
echo RPM信息
rpm -qpi ~/rpmbuild/RPMS/x86_64/rust_http_proxy-${version}-${release}.x86_64.rpm
echo 配置文件
rpm -qpc ~/rpmbuild/RPMS/x86_64/rust_http_proxy-${version}-${release}.x86_64.rpm
echo 所有文件
rpm -qpl ~/rpmbuild/RPMS/x86_64/rust_http_proxy-${version}-${release}.x86_64.rpm
# rpm -ivh在安装新版本时会报错文件冲突，原因是他没有进行更新或降级的能力，而yum install可以处理可执行文件的更新或降级
yum install -y ~/rpmbuild/RPMS/x86_64/rust_http_proxy-${version}-${release}.x86_64.rpm

## 启动
service rust_http_proxy restart
service rust_http_proxy status --no-page
```