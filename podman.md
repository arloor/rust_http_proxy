```shell
tag=1.6
git clone https://github.com/arloor/rust_http_proxy /var/rust_http_proxy
cd /var/rust_http_proxy
git pull
cargo install --path . --target x86_64-unknown-linux-musl
podman build  -t rust_http_proxy -f Dockerfile . --tag ccr.ccs.tencentyun.com/arloor/rust_http_proxy:$tag
podman login ccr.ccs.tencentyun.com -u 1293181335 # 输入账号密码登陆docker hub
podman push ccr.ccs.tencentyun.com/arloor/rust_http_proxy:$tag
```





```bash
systemctl stop proxy
# podman rmi rust_http_proxy

podman run -d \
--rm \
--network host \
--tz=Asia/Shanghai \
--env-file /etc/rust_http_proxy/env \
-v /root/.acme.sh/arloor.dev/:/root/.acme.sh/arloor.dev/ \
-v /usr/share/nginx/html/:/usr/share/nginx/html/ \
-v /tmp:/tmp \
--name proxy \
ccr.ccs.tencentyun.com/arloor/rust_http_proxy:1.0
# 生成systemd文件
podman generate systemd --new --files --name proxy
mv container-proxy.service /lib/systemd/system/proxy.service
systemctl daemon-reload
systemctl enable proxy
systemctl restart proxy

tail -fn 10 /tmp/proxy.log

```