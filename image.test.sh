 cargo build -r --features bpf_vendored
 podman build -f Dockerfile.test -t quay.io/arloor/rust_http_proxy:bpf_vendored . --net host
 podman login quay.io -u arloor 
 podman push quay.io/arloor/rust_http_proxy:bpf_vendored