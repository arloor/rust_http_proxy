#!/usr/bin/python3

import json
import subprocess
import os

token = os.getenv('GH_TOKEN')
if token is None:
    print("github token is null, cannot update github release")
    exit()

# 获取assetId
pipe = subprocess.Popen('curl -L \
  -H "Accept: application/vnd.github+json" \
  -H "Authorization: Bearer ' + token + '" \
  -H "X-GitHub-Api-Version: 2022-11-28" \
  https://api.github.com/repos/arloor/rust_http_proxy/releases/tags/v1.0.0', shell=True, stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE)
res = pipe.stdout.read().decode()
# print(res)
rjson = json.loads(res)
releaseId = rjson['id']
assets = rjson['assets']

# 删除旧的assets
for asset in assets:
    pipe = subprocess.Popen('curl -L \
  -X DELETE \
  -H "Accept: application/vnd.github+json" \
  -H "Authorization: Bearer ' + token + '" \
  -H "X-GitHub-Api-Version: 2022-11-28" \
  https://api.github.com/repos/arloor/rust_http_proxy/releases/assets/' + str(asset['id']), shell=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    err = pipe.stderr.read().decode()

toUploads = {
    'rust_http_proxy': '/var/rust_http_proxy/target/x86_64-unknown-linux-musl/release/rust_http_proxy',
    'rust_http_proxy-0.1-1.all.x86_64.rpm': '/root/rpmbuild/RPMS/x86_64/rust_http_proxy-0.1-1.all.x86_64.rpm'
}
for name in toUploads:
    pipe = subprocess.Popen('curl -L \
  -X POST \
  -H "Accept: application/vnd.github+json" \
  -H "Authorization: Bearer ' + token + '" \
  -H "X-GitHub-Api-Version: 2022-11-28" \
  -H "Content-Type: application/octet-stream" \
  "https://uploads.github.com/repos/arloor/rust_http_proxy/releases/' + str(releaseId) + '/assets?name=' + name + '" \
  --data-binary "@' + toUploads[name] + '"', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    err = pipe.stderr.read().decode()
    out = pipe.stdout.read().decode()
    print("uploading ", name)
    if len(err) != 0:
        print(err)
