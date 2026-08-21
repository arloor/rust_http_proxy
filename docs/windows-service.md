# Windows 服务模式

`rust_http_proxy` 支持以 Windows 服务方式运行。

## 编译 Windows 服务版本

```powershell
cargo build --bin rust_http_proxy_service --features winservice --release
```

## 安装与管理

### 使用仓库更新脚本

管理员 PowerShell 中可使用仓库内脚本重新编译、覆盖服务参数并重启服务：

```powershell
.\deploy\update_windows_service.ps1 `
  -ProxyUser @('username:password', 'another-user:password')
```

脚本会异步发送停止命令并显式等待服务状态，避免 `Stop-Service` 自身的等待行为干扰更新。首次从旧版本升级时，如果服务在 45 秒内仍无法退出，可允许脚本仅针对 SCM 返回的服务 PID 强制终止旧进程：

```powershell
.\deploy\update_windows_service.ps1 `
  -ProxyUser @('username:password', 'another-user:password') `
  -ForceTerminateOnStopTimeout
```

新版本服务收到停止控制后会立即上报 `StopPending`，优雅关闭最多等待 20 秒，再清理剩余异步连接并上报 `Stopped`。

### 使用 sc.exe

```powershell
# 创建服务
sc.exe create rust_http_proxy binPath= "C:\path\to\rust_http_proxy_service.exe -p 7777 -u username:password"

# 启动服务
sc.exe start rust_http_proxy

# 设置自动启动
sc.exe config rust_http_proxy start= auto

# 停止服务
sc.exe stop rust_http_proxy

# 删除服务
sc.exe delete rust_http_proxy
```

### 使用 PowerShell Cmdlet

```powershell
# 创建并配置服务
New-Service -Name "rust_http_proxy" `
  -BinaryPathName "C:\path\to\rust_http_proxy_service.exe -p 7777 -u username:password" `
  -StartupType Automatic `
  -Description "A HTTP proxy server based on Hyper and Rustls"

# 启动服务
Start-Service -Name "rust_http_proxy"

# 停止服务
Stop-Service -Name "rust_http_proxy"

# 删除服务
(Get-WmiObject -Class Win32_Service -Filter "Name='rust_http_proxy'").Delete()

# PowerShell 6.0+ 可使用
# Remove-Service -Name "rust_http_proxy"
```
