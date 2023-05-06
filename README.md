## 下载证书和私钥

```shell
scp root@hk.arloor.dev:/root/.acme.sh/arloor.dev/fullchain.cer ./cert.pem
scp root@hk.arloor.dev:/root/.acme.sh/arloor.dev/arloor.dev.key ./privkey.pem
```

## 转换格式

需要pkcs8的私钥，转换命令为：

```shell
openssl pkcs8 -topk8 -inform PEM -in privkey.pem -out pkcs8_private_key.pem -nocrypt
```

或者使用acme：

```shell
acme.sh -d arloor.dev  --toPkcs8
```

## 部署

```shell
ssh root@hk.arloor.dev -t "
cd ~/rust_http_proxy
git pull
cargo build --release
mv target/release/rust_http_proxy /opt/proxy/
service proxy restart
tail -f /opt/proxy/proxy.log
"

```