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

# Runs in the signed-in user's session, hidden. Captures the whole desktop,
# scales it to at most 1280px wide, uploads it as JPEG, and waits as long as
# the portal says (1s while someone is watching live, 10s otherwise).
_SCREEN_AGENT = r"""$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms, System.Drawing
Add-Type -TypeDefinition 'using System.Runtime.InteropServices; public static class AgDpi { [DllImport("user32.dll")] public static extern bool SetProcessDPIAware(); }'
[AgDpi]::SetProcessDPIAware() | Out-Null

$Url = '__UPLOAD_URL__'
$Token = '__TOKEN__'
$Interval = 10

$codec = [System.Drawing.Imaging.ImageCodecInfo]::GetImageEncoders() | Where-Object { $_.MimeType -eq 'image/jpeg' }
$quality = New-Object System.Drawing.Imaging.EncoderParameters 1
$quality.Param[0] = New-Object System.Drawing.Imaging.EncoderParameter ([System.Drawing.Imaging.Encoder]::Quality, [long]60)

while ($true) {
    try {
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
        if ($reply.next_interval) { $Interval = [Math]::Max(1, [int]$reply.next_interval) }
    } catch {
        # Locked screen, network down, server restarting: just retry later.
        $Interval = 10
    }
    Start-Sleep -Seconds $Interval
}
"""

# Runs once, elevated, from the installer: writes the screen agent and
# registers it for every user (BUILTIN\Users, by SID so it works on any
# Windows language) at logon, then starts it for whoever is signed in now.
_SETUP_SCREEN_AGENT = r"""$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path '__INSTALL_DIR__' | Out-Null
[IO.File]::WriteAllBytes('__AGENT_PATH__', [Convert]::FromBase64String($env:AG_SCREEN_AGENT))
$action = New-ScheduledTaskAction -Execute 'conhost.exe' -Argument '--headless powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "__AGENT_PATH__"'
$trigger = New-ScheduledTaskTrigger -AtLogOn
$principal = New-ScheduledTaskPrincipal -GroupId 'S-1-5-32-545' -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName '__TASK_NAME__' -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
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
echo ============================================================
choice /C YN /M "Install AegisGuard monitoring on this computer"
if errorlevel 2 (
    echo Installation cancelled. Nothing was changed.
    pause
    exit /b 1
)

set "MANAGER={manager}"
set "MSI_URL={msi_url}"
set "AGENT_KEY_LINE={key_line}"
set "AG_SCREEN_AGENT={screen_agent_b64}"
set "MSI=%TEMP%\aegisguard-wazuh-agent.msi"
set "AGENT_DIR=%ProgramFiles(x86)%\ossec-agent"

echo [1/5] Downloading the monitoring agent...
powershell -NoProfile -ExecutionPolicy Bypass -Command "$ProgressPreference='SilentlyContinue'; Invoke-WebRequest -Uri $env:MSI_URL -OutFile $env:MSI"
if %errorlevel% neq 0 goto fail

echo [2/5] Installing...
start "" /wait msiexec /i "%MSI%" /q WAZUH_MANAGER=%MANAGER%
rem 1638 = this version is already installed; the key below still updates it.
if %errorlevel% neq 0 if %errorlevel% neq 1638 goto fail

echo [3/5] Registering this computer with AegisGuard...
net stop WazuhSvc >nul 2>&1
powershell -NoProfile -Command "[IO.File]::WriteAllText($env:AGENT_DIR + '\client.keys', $env:AGENT_KEY_LINE + [char]10)"
if %errorlevel% neq 0 goto fail

echo [4/5] Starting monitoring...
net start WazuhSvc
if %errorlevel% neq 0 goto fail

echo [5/5] Setting up the live screen view...
powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand {setup_encoded}
if %errorlevel% neq 0 goto fail

del "%MSI%" >nul 2>&1
echo.
echo Done. This computer is now monitored by AegisGuard.
pause
exit /b 0

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
        # Base64 keeps the multi-line scripts out of cmd.exe's quoting rules.
        screen_agent_b64=base64.b64encode(screen_agent.encode("utf-8")).decode("ascii"),
        setup_encoded=base64.b64encode(setup.encode("utf-16-le")).decode("ascii"),
    )
    # cmd.exe expects CRLF line endings.
    return script.replace("\r\n", "\n").replace("\n", "\r\n").encode("ascii")
