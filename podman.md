```shell
yum install -y podman docker
podman login docker.io
```


```shell
git pull
cargo install --path . --target x86_64-unknown-linux-musl
podman kill proxy
podman rm proxy
podman rmi rust_http_proxy
podman build -t rust_http_proxy .
## 推送到hub.docker.io
#podman tag rust_http_proxy:latest arloor/rust_http_proxy
#docker push arloor/rust_http_proxy

podman run -d \
--rm \
--network host \
--tz=Asia/Shanghai \
--env-file /etc/rust_http_proxy/env \
-v /root/.acme.sh/arloor.dev/:/root/.acme.sh/arloor.dev/ \
-v /usr/share/nginx/html/:/usr/share/nginx/html/ \
-v /tmp:/tmp \
--name proxy \
rust_http_proxy
# 生成systemd文件
podman generate systemd --new --files --name proxy
mv container-proxy.service /lib/systemd/system/proxy.service
systemctl daemon-reload
systemctl enable proxy
systemctl restart proxy

tail -fn 10 /tmp/proxy.log

```