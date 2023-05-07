## 生成证书和私钥

- 生成证书和PKCS#1私钥

```shell
# 生成PKCS#1私钥
openssl genrsa -out private_key.pem 4096
# 从私钥生成证书
openssl req -x509 -key private_key.pem -sha256 -nodes -out cert.pem -days 3650 -subj "/C=/ST=/L=/O=/OU=/CN=example.com"
```

### 生成证书和PKCS#8私钥

```shell
openssl req -x509 -newkey rsa:4096 -sha256 -nodes -keyout privkey.pem -out cert.pem -days 3650 -subj "/C=/ST=/L=/O=/OU=/CN=example.com"
```

### 生成证书和PKCS#8私钥，并转换成PKCS#1私钥

```shell
openssl req -x509 -newkey rsa:4096 -sha256 -nodes -keyout temp.pem -out cert.pem -days 3650 -subj "/C=/ST=/L=/O=/OU=/CN=example.com"
## 转换成PKCS#1私钥
openssl rsa -inform PEM -in temp.pem -outform PEM -out privkey.pem
```


## 备注：私钥转换格式的常用命令

```shell
# 转换成pkcs8
openssl pkcs8 -topk8 -inform PEM -in privkey.pem -out pkcs8_private_key.pem -outform PEM -nocrypt
# 转换成RSA加密
openssl rsa -inform PEM -in privkey.pem -outform PEM -out rsa_aes_privkey.pem
```