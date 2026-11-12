"""Package a built extension for Chrome and Edge. Requires Python 3.9+."""
import json
from pathlib import Path
import re
import zipfile

root = Path(__file__).resolve().parents[1]
dist = root / "dist-extension"
cargo = (root.parent / "rust_http_proxy" / "Cargo.toml").read_text()
package = re.search(r"(?ms)^\[package\]\s*$(.*?)(?=^\[|\Z)", cargo)
version_field = re.search(r'^version\s*=\s*"([^"\n]+)"', package[1] if package else "", re.MULTILINE)
if version_field is None:
    raise ValueError("Missing explicit [package] version in rust_http_proxy/Cargo.toml")
version = version_field[1]
if not re.fullmatch(r"(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){0,3}", version) or any(int(part) > 65535 for part in version.split(".")) or not any(int(part) for part in version.split(".")):
    raise ValueError(f"Project version is not a valid browser extension version: {version}")

manifest = json.loads((dist / "manifest.json").read_text())
manifest["version"] = version
required = {"index.html", manifest["action"]["default_popup"], *manifest["icons"].values(), *manifest["action"]["default_icon"].values()}
for name in required:
    if not (dist / name).is_file():
        raise FileNotFoundError(f"Missing extension asset: {name}; run npm run build:extension first")

output = root / "release"
output.mkdir(exist_ok=True)
archive = output / f"rust-http-proxy-mitm-extension-v{version}.zip"
# Write the release version into the archive only; leave the development build intact.
with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
    for path in sorted(dist.rglob("*")):
        if path.is_file():
            name = path.relative_to(dist).as_posix()
            if name == "manifest.json":
                bundle.writestr(name, json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")
            else:
                bundle.write(path, name)
with zipfile.ZipFile(archive) as bundle:
    if bundle.testzip() is not None:
        raise RuntimeError("Extension ZIP integrity check failed")
print(archive)
