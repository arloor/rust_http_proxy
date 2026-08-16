#requires -RunAsAdministrator

[CmdletBinding()]
param(
    [string]$Repo = 'C:\Users\arloor\rust_http_proxy',
    [string]$Cargo = 'C:\Users\arloor\.cargo\bin\cargo.exe',
    [string]$ServiceName = 'rust_http_proxy',
    [string]$Exe = 'C:\Users\arloor\.cargo\bin\rust_http_proxy_service.exe',
    [string]$CaCert = 'C:\ProgramData\rust_http_proxy\mitm\mitm-ca-cert.pem',
    [string]$CaKey = 'C:\ProgramData\rust_http_proxy\mitm\mitm-ca-key.pem',
    [int[]]$Port = @(443, 444, 9443),
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string[]]$ProxyUser,
    [ValidateRange(10, 300)]
    [int]$StopTimeoutSeconds = 45,
    [ValidateRange(10, 300)]
    [int]$StartTimeoutSeconds = 30,
    [switch]$ForceTerminateOnStopTimeout
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Quote-ServiceArgument {
    param([Parameter(Mandatory)][string]$Value)

    if ($Value.Contains('"')) {
        throw "服务参数不能包含双引号：$Value"
    }
    return '"' + $Value + '"'
}

function Get-ServiceCimInfo {
    param([Parameter(Mandatory)][string]$Name)

    return Get-CimInstance -ClassName Win32_Service -ErrorAction Stop |
        Where-Object { $_.Name -eq $Name } |
        Select-Object -First 1
}

function Wait-ServiceState {
    param(
        [Parameter(Mandatory)][System.ServiceProcess.ServiceController]$Service,
        [Parameter(Mandatory)][System.ServiceProcess.ServiceControllerStatus]$Status,
        [Parameter(Mandatory)][int]$TimeoutSeconds
    )

    $Service.Refresh()
    $Service.WaitForStatus($Status, [TimeSpan]::FromSeconds($TimeoutSeconds))
    $Service.Refresh()
    if ($Service.Status -ne $Status) {
        throw "服务状态未变为 $Status，当前状态：$($Service.Status)"
    }
}

function Stop-ServiceForUpdate {
    param(
        [Parameter(Mandatory)][System.ServiceProcess.ServiceController]$Service,
        [Parameter(Mandatory)][int]$TimeoutSeconds,
        [Parameter(Mandatory)][bool]$AllowForceTerminate
    )

    $Service.Refresh()
    if ($Service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Stopped) {
        return
    }

    Write-Host "正在停止服务 $($Service.ServiceName)…"
    try {
        Stop-Service -InputObject $Service -NoWait -ErrorAction Stop
        Wait-ServiceState -Service $Service `
            -Status ([System.ServiceProcess.ServiceControllerStatus]::Stopped) `
            -TimeoutSeconds $TimeoutSeconds
    }
    catch {
        $stopErrorMessage = $_.Exception.Message
        $Service.Refresh()
        $serviceInfo = Get-ServiceCimInfo -Name $Service.ServiceName
        $serviceProcessId = if ($null -eq $serviceInfo) { 0 } else { [int]$serviceInfo.ProcessId }
        if (-not $AllowForceTerminate -or $serviceProcessId -le 0) {
            throw "服务停止失败或在 $TimeoutSeconds 秒内未停止；当前状态=$($Service.Status)，PID=$serviceProcessId，原因=$stopErrorMessage。首次升级旧版本时可加 -ForceTerminateOnStopTimeout。"
        }

        Write-Warning "服务未在 $TimeoutSeconds 秒内停止，正在强制终止服务进程 PID=$serviceProcessId"
        Stop-Process -Id $serviceProcessId -Force -ErrorAction Stop
        Wait-ServiceState -Service $Service `
            -Status ([System.ServiceProcess.ServiceControllerStatus]::Stopped) `
            -TimeoutSeconds 15
    }
}

function Invoke-ScConfig {
    param(
        [Parameter(Mandatory)][string[]]$ScArguments,
        [Parameter(Mandatory)][string]$FailureMessage
    )

    & sc.exe @ScArguments
    if ($LASTEXITCODE -ne 0) {
        throw "$FailureMessage，sc.exe 退出码：$LASTEXITCODE"
    }
}

$serverCert = Join-Path $Repo 'cert.pem'
$serverKey = Join-Path $Repo 'privkey.pem'
$cratePath = Join-Path $Repo 'rust_http_proxy'

foreach ($requiredPath in @($Repo, $Cargo, $CaCert, $CaKey, $serverCert, $serverKey, $cratePath)) {
    if (-not (Test-Path -LiteralPath $requiredPath)) {
        throw "缺少必要路径：$requiredPath"
    }
}
foreach ($user in $ProxyUser) {
    if ([string]::IsNullOrWhiteSpace($user)) {
        throw 'ProxyUser 不能包含空值'
    }
}

$service = Get-Service -Name $ServiceName -ErrorAction Stop
$stage = '停止服务'

try {
    Stop-ServiceForUpdate -Service $service `
        -TimeoutSeconds $StopTimeoutSeconds `
        -AllowForceTerminate $ForceTerminateOnStopTimeout.IsPresent

    $stage = '编译并安装服务程序'
    Set-Location -LiteralPath $Repo
    & $Cargo install `
        --force `
        --path $cratePath `
        --bin rust_http_proxy_service `
        --features winservice
    if ($LASTEXITCODE -ne 0) {
        throw "cargo install 失败，退出码：$LASTEXITCODE"
    }
    if (-not (Test-Path -LiteralPath $Exe -PathType Leaf)) {
        throw "cargo install 完成，但未找到服务程序：$Exe"
    }

    $binParts = [System.Collections.Generic.List[string]]::new()
    $binParts.Add((Quote-ServiceArgument -Value $Exe))
    foreach ($listenPort in $Port) {
        if ($listenPort -lt 1 -or $listenPort -gt 65535) {
            throw "端口超出有效范围：$listenPort"
        }
        $binParts.Add('-p')
        $binParts.Add($listenPort.ToString([Globalization.CultureInfo]::InvariantCulture))
    }
    $binParts.Add('-k')
    $binParts.Add((Quote-ServiceArgument -Value $serverKey))
    $binParts.Add('-c')
    $binParts.Add((Quote-ServiceArgument -Value $serverCert))
    $binParts.Add('-o')
    foreach ($user in $ProxyUser) {
        $binParts.Add('-u')
        $binParts.Add((Quote-ServiceArgument -Value $user))
    }
    $binParts.Add('--mitm-dump')
    $binParts.Add('--mitm-ca-cert')
    $binParts.Add((Quote-ServiceArgument -Value $CaCert))
    $binParts.Add('--mitm-ca-key')
    $binParts.Add((Quote-ServiceArgument -Value $CaKey))
    $binPath = $binParts -join ' '

    $stage = '覆盖服务参数'
    Invoke-ScConfig -ScArguments @('config', $ServiceName, 'binPath=', $binPath) `
        -FailureMessage '覆盖服务参数失败'
    Invoke-ScConfig -ScArguments @('config', $ServiceName, 'start=', 'auto') `
        -FailureMessage '设置自动启动失败'

    $stage = '启动服务'
    $service.Refresh()
    Start-Service -InputObject $service -ErrorAction Stop
    Wait-ServiceState -Service $service `
        -Status ([System.ServiceProcess.ServiceControllerStatus]::Running) `
        -TimeoutSeconds $StartTimeoutSeconds

    $serviceInfo = Get-ServiceCimInfo -Name $ServiceName
    Write-Host "`n更新成功：" -ForegroundColor Green
    [pscustomobject]@{
        Name       = $serviceInfo.Name
        State      = $serviceInfo.State
        StartMode  = $serviceInfo.StartMode
        ProcessId  = $serviceInfo.ProcessId
        Executable = $Exe
    } | Format-List
}
catch {
    Write-Host "`n更新失败（$stage）：$($_.Exception.Message)" -ForegroundColor Red

    $recoveryService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($null -ne $recoveryService -and $recoveryService.Status -eq 'Stopped') {
        try {
            Write-Host '正在尝试恢复服务运行…' -ForegroundColor Yellow
            Start-Service -InputObject $recoveryService -ErrorAction Stop
            Wait-ServiceState -Service $recoveryService `
                -Status ([System.ServiceProcess.ServiceControllerStatus]::Running) `
                -TimeoutSeconds $StartTimeoutSeconds
        }
        catch {
            Write-Host "服务恢复启动也失败：$($_.Exception.Message)" -ForegroundColor Red
        }
    }

    throw
}
