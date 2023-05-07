## 生成证书和私钥

```shell
openssl req -x509 -newkey rsa:4096 -sha256 -nodes -keyout temp.pem -out cert.pem -days 3650 -subj "/C=/ST=/L=/O=/OU=/CN=example.com"
## 将私钥进行RSA加密（本程序需要RSA加密的私钥）
openssl rsa -inform PEM -in temp.pem -outform PEM -out privkey.pem
```

```shell
openssl req -x509 -newkey rsa:4096 -sha256 -nodes -keyout privkey.pem -out cert.pem -days 3650 -subj "/C=/ST=/L=/O=/OU=/CN=example.com"

```

## 备注：私钥转换格式的常用命令

```shell
# 转换成pkcs8
openssl pkcs8 -topk8 -inform PEM -in privkey.pem -out pkcs8_private_key.pem -outform PEM -nocrypt
# 转换成RSA加密
openssl rsa -inform PEM -in privkey.pem -outform PEM -out rsa_aes_privkey.pem
```