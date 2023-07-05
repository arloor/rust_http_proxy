```shell
yum install -y podman docker
```


```shell
git pull
cargo install --path . --target x86_64-unknown-linux-musl
podman kill proxy
podman rm proxy
podman rmi rust_http_proxy
podman build -t rust_http_proxy .
podman run -d --network host --env-file /etc/rust_http_proxy/env -v /root/.acme.sh/arloor.dev/:/root/.acme.sh/arloor.dev/ -v /usr/share/nginx/html/:/usr/share/nginx/html/ -v /tmp:/tmp --name proxy rust_http_proxy
tail -fn 10 /tmp/proxy.log
```