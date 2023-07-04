
```shell
podman build -t rust_http_proxy .
podman run -d --env-file /etc/rust_http_proxy/env -p 443:443 -v /root/.acme.sh/arloor.dev/:/root/.acme.sh/arloor.dev/ -v /usr/share/nginx/html/:/usr/share/nginx/html/ -v /tmp:/tmp --name proxy rust_http_proxy
podman exec -it proxy /bin/sh
podman kill proxy
podman rm --all
```