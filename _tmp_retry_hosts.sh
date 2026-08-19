#!/usr/bin/env bash
set -euo pipefail
hosts=(us.arloor.dev hk.arloor.dev ti.arloor.dev bj.arloor.com sh.arloor.com)
for host in "${hosts[@]}"; do
  echo "=== retry ${host} ==="
  ssh -o StrictHostKeyChecking=no -o ConnectTimeout=20 "root@${host}" 'bash -se' <<'EOFEOF'
. pass | true
hostname
systemctl restart proxy
podman rmi -a 2>/dev/null || true
podman images --digests | awk '/arloor\/rust_http_proxy/ {print $4, $3}'
EOFEOF
done
echo "=== remaining hosts done ==="
