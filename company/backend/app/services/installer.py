"""Builds the per-endpoint one-click Windows installer (.cmd).

Each file embeds that endpoint's own Wazuh agent key and screen-upload
token, so it's a credential: whoever runs it gets a computer enrolled as
this endpoint. It shows a monitoring notice that must be accepted, installs
the Wazuh agent, writes the key into client.keys (so no open self-enrollment
is needed), and installs the screen agent as a hidden task that runs in each
user's session at logon (a Windows service can't capture the desktop).
"""

import base64
import re

from app.core.config import settings

INSTALL_DIR = r"C:\Program Files\AegisGuard"
SCREEN_AGENT_PATH = INSTALL_DIR + r"\screen-agent.ps1"
TASK_NAME = "AegisGuard Screen Agent"

# Runs in the signed-in user's session, hidden: uploads screenshots for Live
# Monitoring and, while the employee account is Locked in the portal, covers
# the screen with a lock and blocks keyboard and mouse input until it is
# unlocked there. See the comments inside the script.
_SCREEN_AGENT = r"""$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms, System.Drawing
Add-Type -TypeDefinition 'using System.Runtime.InteropServices; public static class AgDpi { [DllImport("user32.dll")] public static extern bool SetProcessDPIAware(); }'
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
// While the computer is locked: swallow every keyboard and mouse event with
// low-level hooks (no administrator rights needed). Ctrl+Alt+Del can't be
// blocked by any program; the lock survives it, see the agent's main loop.
public static class AgInput {
    public delegate IntPtr HookProc(int code, IntPtr wParam, IntPtr lParam);
    [DllImport("user32.dll", SetLastError = true)] static extern IntPtr SetWindowsHookEx(int id, HookProc proc, IntPtr module, uint thread);
    [DllImport("user32.dll")] static extern bool UnhookWindowsHookEx(IntPtr hook);
    [DllImport("user32.dll")] static extern IntPtr CallNextHookEx(IntPtr hook, int code, IntPtr wParam, IntPtr lParam);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] static extern IntPtr GetModuleHandle(string name);
    static HookProc swallow = Swallow;
    static IntPtr keyboard = IntPtr.Zero;
    static IntPtr mouse = IntPtr.Zero;
    static IntPtr Swallow(int code, IntPtr wParam, IntPtr lParam) {
        if (code < 0) return CallNextHookEx(IntPtr.Zero, code, wParam, lParam);
        return (IntPtr)1;
    }
    public static void Block() {
        if (keyboard != IntPtr.Zero) return;
        IntPtr module = GetModuleHandle(null);
        keyboard = SetWindowsHookEx(13, swallow, module, 0);
        mouse = SetWindowsHookEx(14, swallow, module, 0);
    }
    public static void Release() {
        if (keyboard != IntPtr.Zero) { UnhookWindowsHookEx(keyboard); keyboard = IntPtr.Zero; }
        if (mouse != IntPtr.Zero) { UnhookWindowsHookEx(mouse); mouse = IntPtr.Zero; }
    }
}
'@
[AgDpi]::SetProcessDPIAware() | Out-Null

$Url = '__UPLOAD_URL__'
$Token = '__TOKEN__'
$StatusUrl = $Url -replace '/screen$', '/status'
$Interval = 10

# Lock state lives on the server (an employee account that is Locked in the
# portal); this registry value only remembers it for when the portal can't be
# reached, so a locked computer stays locked offline and across restarts.
$MarkerKey = 'HKCU:\Software\AegisGuard'
$PolicyKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
# Emergency release for a local administrator: creating this file (it needs
# administrator rights to write there) switches the lock off.
$BreakGlass = 'C:\Program Files\AegisGuard\disable-lock'

$codec = [System.Drawing.Imaging.ImageCodecInfo]::GetImageEncoders() | Where-Object { $_.MimeType -eq 'image/jpeg' }
$quality = New-Object System.Drawing.Imaging.EncoderParameters 1
$quality.Param[0] = New-Object System.Drawing.Imaging.EncoderParameter ([System.Drawing.Imaging.Encoder]::Quality, [long]60)

function Set-LocalLock([bool]$On) {
    try {
        if ($On) {
            New-Item -Path $MarkerKey -Force | Out-Null
            Set-ItemProperty -Path $MarkerKey -Name Locked -Value 1 -Type DWord
        } else {
            Remove-ItemProperty -Path $MarkerKey -Name Locked -ErrorAction SilentlyContinue
        }
    } catch {}
}

function Get-LocalLock {
    try { return ((Get-ItemProperty -Path $MarkerKey -Name Locked -ErrorAction Stop).Locked -eq 1) } catch { return $false }
}

# Task Manager is the one way a user could end this agent, so it is switched
# off for their account while the computer is locked.
function Set-TaskManager([bool]$Disabled) {
    try {
        if ($Disabled) {
            New-Item -Path $PolicyKey -Force | Out-Null
            Set-ItemProperty -Path $PolicyKey -Name DisableTaskMgr -Value 1 -Type DWord
        } else {
            Remove-ItemProperty -Path $PolicyKey -Name DisableTaskMgr -ErrorAction SilentlyContinue
        }
    } catch {}
}

function Get-Locked {
    if (Test-Path $BreakGlass) { Set-LocalLock $false; return $false }
    try {
        $reply = Invoke-RestMethod -Uri $StatusUrl -Method Get -Headers @{ 'X-AegisGuard-Token' = $Token } -TimeoutSec 5
        $locked = [bool]$reply.locked
        Set-LocalLock $locked
        return $locked
    } catch {
        $code = $null
        try { $code = [int]$_.Exception.Response.StatusCode } catch {}
        # This computer was removed from the portal: nobody is left to unlock it.
        if ($code -eq 401) { Set-LocalLock $false; return $false }
        # Portal unreachable: stay as we were. A locked computer stays locked.
        return (Get-LocalLock)
    }
}

# Full-screen lock with all input blocked. Blocks until the portal says the
# computer is unlocked (polled in the background so the hooks never stall).
function Show-Lock {
    Set-TaskManager $true
    $state = @{ Pending = $null; Unlocked = $false }

    $form = New-Object System.Windows.Forms.Form
    $form.FormBorderStyle = 'None'
    $form.StartPosition = 'Manual'
    $form.ShowInTaskbar = $false
    $form.TopMost = $true
    $form.BackColor = [System.Drawing.Color]::FromArgb(20, 6, 10)
    $area = [System.Windows.Forms.SystemInformation]::VirtualScreen
    $form.Location = New-Object System.Drawing.Point $area.Left, $area.Top
    $form.Size = New-Object System.Drawing.Size $area.Width, $area.Height

    $title = New-Object System.Windows.Forms.Label
    $title.Dock = 'Fill'
    $title.TextAlign = 'MiddleCenter'
    $title.ForeColor = [System.Drawing.Color]::FromArgb(251, 113, 133)
    $title.Font = New-Object System.Drawing.Font 'Segoe UI', 30, ([System.Drawing.FontStyle]::Bold)
    $title.Text = "THIS COMPUTER IS LOCKED`r`n`r`nYour administrator has locked this computer.`r`nContact your administrator to unlock it."
    $form.Controls.Add($title)

    $form.Add_FormClosing({
        param($sender, $e)
        if (-not $state.Unlocked -and ($e.CloseReason -eq 'UserClosing' -or $e.CloseReason -eq 'None')) { $e.Cancel = $true }
    })
    $form.Add_Shown({ $form.Activate() })

    $timer = New-Object System.Windows.Forms.Timer
    $timer.Interval = 2000
    $timer.Add_Tick({
        $form.TopMost = $true
        if (Test-Path $BreakGlass) { $state.Unlocked = $true; $form.Close(); return }
        $task = $state.Pending
        if ($task -ne $null) {
            if (-not $task.IsCompleted) { return }
            $state.Pending = $null
            if (-not $task.IsFaulted -and -not $task.IsCanceled) {
                try {
                    if (-not [bool](($task.Result | ConvertFrom-Json).locked)) { $state.Unlocked = $true; $form.Close(); return }
                } catch {}
            }
        }
        $client = New-Object System.Net.WebClient
        $client.Headers.Add('X-AegisGuard-Token', $Token)
        $state.Pending = $client.DownloadStringTaskAsync($StatusUrl)
    })

    try {
        [AgInput]::Block()
        [System.Windows.Forms.Cursor]::Hide()
        $timer.Start()
        [System.Windows.Forms.Application]::Run($form)
    } finally {
        $timer.Stop()
        [AgInput]::Release()
        [System.Windows.Forms.Cursor]::Show()
        $form.Dispose()
        Set-TaskManager $false
        Set-LocalLock $false
    }
}

function Send-Frame {
    $area = [System.Windows.Forms.SystemInformation]::VirtualScreen
    $full = New-Object System.Drawing.Bitmap $area.Width, $area.Height
    $graphics = [System.Drawing.Graphics]::FromImage($full)
    $graphics.CopyFromScreen($area.Left, $area.Top, 0, 0, $full.Size)
    $graphics.Dispose()

    $width = [Math]::Min(1280, $area.Width)
    $height = [int]($area.Height * $width / $area.Width)
    $frame = New-Object System.Drawing.Bitmap $full, $width, $height
    $full.Dispose()

    $stream = New-Object System.IO.MemoryStream
    $frame.Save($stream, $codec, $quality)
    $frame.Dispose()

    $reply = Invoke-RestMethod -Uri $Url -Method Post -Body $stream.ToArray() -ContentType 'image/jpeg' -Headers @{ 'X-AegisGuard-Token' = $Token } -TimeoutSec 10
    $stream.Dispose()
    return $reply
}

# --- main loop ---
# Captures the whole desktop, scales it to at most 1280px wide, uploads it as
# JPEG, and waits as long as the portal says (1s while someone is watching
# live, 10s otherwise). Every few seconds it also asks whether the computer
# has been locked.
# A computer that is already locked when the agent starts (after a restart or a
# sign-out) is locked straight away; otherwise undo what a crash during a lock
# may have left behind.
if (Get-Locked) { Show-Lock } else { Set-TaskManager $false }
$sinceFrame = $Interval
$sinceStatus = 0
while ($true) {
    if ($sinceStatus -ge 3) {
        $sinceStatus = 0
        if (Get-Locked) { Show-Lock; $sinceFrame = $Interval }
    }
    if ($sinceFrame -ge $Interval) {
        $sinceFrame = 0
        try {
            $reply = Send-Frame
            if ($reply.next_interval) { $Interval = [Math]::Max(1, [int]$reply.next_interval) }
        } catch {
            # Locked screen, network down, server restarting: just retry later.
            $Interval = 10
        }
    }
    Start-Sleep -Seconds 1
    $sinceFrame++
    $sinceStatus++
}
"""

# Runs once, elevated, from the installer: writes the screen agent and
# registers it for every user (BUILTIN\Users, by SID so it works on any
# Windows language) at logon, then starts it for whoever is signed in now.
_SETUP_SCREEN_AGENT = r"""$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path '__INSTALL_DIR__' | Out-Null
[IO.File]::WriteAllBytes('__AGENT_PATH__', [Convert]::FromBase64String($env:AG_SCREEN_AGENT))
$action = New-ScheduledTaskAction -Execute 'conhost.exe' -Argument '--headless powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -STA -File "__AGENT_PATH__"'
$trigger = New-ScheduledTaskTrigger -AtLogOn
$principal = New-ScheduledTaskPrincipal -GroupId 'S-1-5-32-545' -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName '__TASK_NAME__' -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
# On a re-install the already-running agent keeps its OLD upload token in
# memory, and MultipleInstances IgnoreNew makes Start a no-op, so it would
# keep sending the stale token (401). Stop the task and kill any lingering
# agent process first, so the fresh instance below reads the new token.
Stop-ScheduledTask -TaskName '__TASK_NAME__' -ErrorAction SilentlyContinue
Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -like '*__AGENT_PATH__*' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
Start-ScheduledTask -TaskName '__TASK_NAME__'
"""

_TEMPLATE = r"""@echo off
setlocal
rem ============================================================
rem  AegisGuard endpoint installer
rem  Company  : {company}
rem  Employee : {employee}
rem  This file contains this computer's secret keys.
rem  Keep it private and delete it after installation.
rem ============================================================

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrator permission...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

echo ============================================================
echo  AegisGuard endpoint monitoring - notice
echo ============================================================
echo  This computer is being enrolled in AegisGuard by
echo  {company}.
echo.
echo  Once installed, the company's security team will be able to:
echo    - collect security events and system logs from this computer
echo    - view this computer's screen in real time
echo.
echo  Monitoring follows your organisation's IT and privacy policy.
echo  Continue only if the user of this computer has been informed.
echo.
echo  NOTE: so that the live screen view and the lock screen can run,
echo  this installer adds the AegisGuard folder to the Windows
echo  Defender exclusions.
echo ============================================================
choice /C YN /M "Install AegisGuard monitoring on this computer"
if errorlevel 2 (
    echo Installation cancelled. Nothing was changed.
    pause
    exit /b 1
)

rem Tell AegisGuard an install has started, so what this installer does
rem (PowerShell, registry and audit changes) isn't judged as suspicious
rem behavior and can't lock this computer. Failure to reach it is ignored.
set "AG_MAINT_URL={maintenance_url}"
set "AG_TOKEN={screen_token}"
powershell -NoProfile -Command "try {{ Invoke-RestMethod -Uri $env:AG_MAINT_URL -Method Post -Headers @{{'X-AegisGuard-Token'=$env:AG_TOKEN}} -TimeoutSec 10 | Out-Null }} catch {{}}"

set "MANAGER={manager}"
set "MSI_URL={msi_url}"
set "AGENT_KEY_LINE={key_line}"
set "AG_SCREEN_AGENT={screen_agent_b64}"
set "MSI=%TEMP%\aegisguard-wazuh-agent.msi"
set "AGENT_DIR=%ProgramFiles(x86)%\ossec-agent"

rem Already enrolled on this computer? Skip the download/install (no internet
rem needed) and just re-key it to this endpoint.
sc query WazuhSvc >nul 2>&1
if %errorlevel% equ 0 (
    echo [1/6] Monitoring agent already installed - skipping download.
    echo [2/6] Skipping install.
    goto configure
)

echo [1/6] Downloading the monitoring agent...
powershell -NoProfile -ExecutionPolicy Bypass -Command "$ProgressPreference='SilentlyContinue'; Invoke-WebRequest -Uri $env:MSI_URL -OutFile $env:MSI"
if %errorlevel% neq 0 goto faildownload

echo [2/6] Installing...
start "" /wait msiexec /i "%MSI%" /q WAZUH_MANAGER=%MANAGER%
rem 1638 = this version is already installed; the key below still updates it.
if %errorlevel% neq 0 if %errorlevel% neq 1638 goto fail

:configure
echo [3/6] Registering this computer with AegisGuard...
net stop WazuhSvc >nul 2>&1
powershell -NoProfile -Command "[IO.File]::WriteAllText($env:AGENT_DIR + '\client.keys', $env:AGENT_KEY_LINE + [char]10)"
if %errorlevel% neq 0 goto fail

echo [4/6] Starting monitoring...
net start WazuhSvc
if %errorlevel% neq 0 goto fail

echo [5/6] Enabling process auditing for behavior monitoring...
rem Windows Event 4688 (process creation) feeds the behavioral anomaly model
rem so it learns which programs each computer normally runs. Use the
rem subcategory GUID, not its English name, so this works on non-English
rem (e.g. Chinese) Windows too. Best-effort: never fail the install over it.
auditpol /set /subcategory:"{{0CCE922B-69AE-11D9-BED3-505054503030}}" /success:enable /failure:enable >nul 2>&1
rem Event 4625 (failed logon) feeds the "3 wrong passwords" alert.
auditpol /set /subcategory:"{{0CCE9215-69AE-11D9-BED3-505054503030}}" /success:enable /failure:enable >nul 2>&1
rem Include the command line in 4688 events (e.g. "powershell -enc ...").
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f >nul 2>&1

echo [6/6] Setting up the live screen view...
rem Defender would block the screen component, so exclude its folder first.
rem If Windows Tamper Protection refuses, the manual steps are shown at the end.
powershell -NoProfile -Command "try {{ Add-MpPreference -ExclusionPath '{install_dir}' }} catch {{}}" >nul 2>&1
powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand {setup_encoded}
if %errorlevel% neq 0 goto fail

del "%MSI%" >nul 2>&1
echo.
echo Done. Security monitoring is active on this computer.
echo.
powershell -NoProfile -Command "if ((Get-MpPreference).ExclusionPath -contains '{install_dir}') {{ exit 0 }} else {{ exit 1 }}"
if %errorlevel% equ 0 (
    echo Live screen view is active.
) else (
    echo ------------------------------------------------------------
    echo  ACTION REQUIRED - enable the live screen view
    echo ------------------------------------------------------------
    echo  Windows Defender is blocking the screen component. An
    echo  administrator must allow it once. Open PowerShell as
    echo  administrator and run these two commands:
    echo.
    echo     Add-MpPreference -ExclusionPath "{install_dir}"
    echo     Start-ScheduledTask -TaskName "{task_name}"
    echo.
    echo  Security event collection already works without this step.
    echo ------------------------------------------------------------
)
pause
exit /b 0

:faildownload
echo.
echo Could not download the monitoring agent. This computer needs
echo internet access to install it for the first time. Check the
echo network connection and run this installer again.
pause
exit /b 1

:fail
echo.
echo Installation failed. Please contact your company administrator.
pause
exit /b 1
"""


def _comment_safe(text: str) -> str:
    # Shown in rem/echo lines: cmd.exe reacts to % & | < > ^ and the file is
    # ASCII, so keep it to plain characters.
    return re.sub(r"[^A-Za-z0-9 ._@()-]", "?", text)


def build_installer(company: str, employee: str, key_line: str, screen_token: str) -> bytes:
    upload_url = settings.portal_public_url.rstrip("/") + "/api/agent/screen"
    screen_agent = _SCREEN_AGENT.replace("__UPLOAD_URL__", upload_url).replace("__TOKEN__", screen_token)
    setup = (
        _SETUP_SCREEN_AGENT.replace("__INSTALL_DIR__", INSTALL_DIR)
        .replace("__AGENT_PATH__", SCREEN_AGENT_PATH)
        .replace("__TASK_NAME__", TASK_NAME)
    )
    script = _TEMPLATE.format(
        company=_comment_safe(company),
        employee=_comment_safe(employee),
        manager=settings.wazuh_manager_address,
        msi_url=settings.wazuh_agent_msi_url,
        key_line=key_line,
        maintenance_url=settings.portal_public_url.rstrip("/") + "/api/agent/maintenance",
        screen_token=screen_token,
        install_dir=INSTALL_DIR,
        task_name=TASK_NAME,
        # Base64 keeps the multi-line scripts out of cmd.exe's quoting rules.
        screen_agent_b64=base64.b64encode(screen_agent.encode("utf-8")).decode("ascii"),
        setup_encoded=base64.b64encode(setup.encode("utf-16-le")).decode("ascii"),
    )
    # cmd.exe expects CRLF line endings.
    return script.replace("\r\n", "\n").replace("\n", "\r\n").encode("ascii")
