#! /usr/bin/python3

import json
import subprocess
import os

token = os.getenv('GH_TOKEN')
if token is None:
    print("github token is null, cannot update github release")
    exit()
else:
    print(f"Github token is {token}")

# 可以变更为其他版本
releaseVersion = 'v1.0.0'
print(f"update assets of release:{releaseVersion}")

# 获取assetId
pipe = subprocess.Popen(f'curl -sSLf \
  -H "Accept: application/vnd.github+json" \
  -H "Authorization: Bearer {token}" \
  -H "X-GitHub-Api-Version: 2022-11-28" \
  https://api.github.com/repos/arloor/rust_http_proxy/releases/tags/{releaseVersion}', shell=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE)
res = pipe.stdout.read().decode()
rjson = json.loads(res)
releaseId = str(rjson.get('id'))
assets = rjson.get('assets')
if len(assets) != 0:
    assets = list(map(lambda x: {'id': x.get('id'), 'name': x.get('name')}, assets))
    print(
        f"current release meta: releaseId:{releaseId}, assets:{json.dumps(assets)}")

# 删除旧的assets
for asset in assets:
    assetId = asset.get("id")
    assetName = asset.get("name")
    print(f"deleting asset: {assetName}({assetId})")
    pipe = subprocess.Popen(f'curl -sSLf \
  -X DELETE \
  -H "Accept: application/vnd.github+json" \
  -H "Authorization: Bearer {token}" \
  -H "X-GitHub-Api-Version: 2022-11-28" \
  https://api.github.com/repos/arloor/rust_http_proxy/releases/assets/{assetId}', shell=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    err = pipe.stderr.read().decode()
    if len(err) != 0:
        print(err)

toUploads = {
    'rust_http_proxy': '/var/rust_http_proxy/target/x86_64-unknown-linux-musl/release/rust_http_proxy',
    'rust_http_proxy-0.1-1.all.x86_64.rpm': '/root/rpmbuild/RPMS/x86_64/rust_http_proxy-0.1-1.all.x86_64.rpm'
}
for name in toUploads:
    print(f"uploading {name}")
    pipe = subprocess.Popen(f'curl -sSLf \
  -X POST \
  -H "Accept: application/vnd.github+json" \
  -H "Authorization: Bearer {token}" \
  -H "X-GitHub-Api-Version: 2022-11-28" \
  -H "Content-Type: application/octet-stream" \
  "https://uploads.github.com/repos/arloor/rust_http_proxy/releases/{releaseId}/assets?name={name}" \
  --data-binary "@{toUploads.get(name)}"', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    err = pipe.stderr.read().decode()
    if len(err) != 0:
        print(err)
    else:
        print(f"uploaded {name}")
