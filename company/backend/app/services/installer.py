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
REMOVAL_TASK_NAME = "AegisGuard Removal Check"
REMOVAL_AGENT_PATH = INSTALL_DIR + r"\remove-agent.ps1"
# Longest piece of Base64 put on one line of the .cmd (cmd's limit is 8191 per line).
_CMD_CHUNK = 6000

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

# What a locked computer shows: plain centred text on a dark background.
function New-LockForm {
    $form = New-Object System.Windows.Forms.Form
    $form.FormBorderStyle = 'None'
    $form.StartPosition = 'Manual'
    $form.ShowInTaskbar = $false
    $form.BackColor = [System.Drawing.Color]::FromArgb(11, 15, 26)

    $layout = New-Object System.Windows.Forms.TableLayoutPanel
    $layout.Dock = 'Fill'
    $layout.ColumnCount = 1
    $layout.RowCount = 4
    [void]$layout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
    [void]$layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 50)))
    [void]$layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))
    [void]$layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))
    [void]$layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 50)))

    $title = New-Object System.Windows.Forms.Label
    $title.Text = 'This computer is locked'
    $title.AutoSize = $true
    $title.Anchor = 'None'
    $title.Font = New-Object System.Drawing.Font('Segoe UI Semibold', 26)
    $title.ForeColor = [System.Drawing.Color]::FromArgb(241, 245, 249)
    $title.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 12)
    $layout.Controls.Add($title, 0, 1)

    $body = New-Object System.Windows.Forms.Label
    $body.Text = 'Contact your administrator to unlock it.'
    $body.AutoSize = $true
    $body.Anchor = 'None'
    $body.Font = New-Object System.Drawing.Font('Segoe UI', 13)
    $body.ForeColor = [System.Drawing.Color]::FromArgb(148, 163, 184)
    $layout.Controls.Add($body, 0, 2)

    $footer = New-Object System.Windows.Forms.Label
    $footer.Text = 'AegisGuard'
    $footer.Dock = 'Bottom'
    $footer.Height = 56
    $footer.TextAlign = 'MiddleCenter'
    $footer.Font = New-Object System.Drawing.Font('Segoe UI', 10)
    $footer.ForeColor = [System.Drawing.Color]::FromArgb(91, 100, 120)

    $form.Controls.Add($layout)
    $form.Controls.Add($footer)
    return $form
}

# Full-screen lock with all input blocked. Blocks until the portal says the
# computer is unlocked (polled in the background so the hooks never stall).
function Show-Lock {
    Set-TaskManager $true
    $state = @{ Pending = $null; Unlocked = $false }

    $form = New-LockForm
    $form.TopMost = $true
    $area = [System.Windows.Forms.SystemInformation]::VirtualScreen
    $form.Location = New-Object System.Drawing.Point $area.Left, $area.Top
    $form.Size = New-Object System.Drawing.Size $area.Width, $area.Height

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
[IO.File]::WriteAllBytes('__AGENT_PATH__', [Convert]::FromBase64String(__AGENT_B64__))
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

# Runs as SYSTEM on the endpoint (see the comments inside the script).
_REMOVAL_AGENT = r"""# Runs as SYSTEM every few minutes (scheduled task). Asks the portal whether this
# computer's employee account has been deleted, and only when the portal says so
# explicitly, uninstalls AegisGuard. Being offline, a refused request or any
# error does nothing at all: a missing connection is never a reason to remove it.
$StatusUrl = '__STATUS_URL__'
$Token = '__TOKEN__'
$InstallDir = '__INSTALL_DIR__'
$ScreenTask = '__TASK_NAME__'
$RemovalTask = '__REMOVAL_TASK_NAME__'
$DryRun = $false
$Log = Join-Path $env:ProgramData 'AegisGuard-removal.log'

function Step([string]$What, [scriptblock]$Do) {
    Add-Content -Path $Log -Value ('[{0}] {1}' -f (Get-Date -Format s), $What)
    if ($DryRun) { Write-Output ('DRY RUN: ' + $What); return }
    try { & $Do } catch { Add-Content -Path $Log -Value ('    failed: ' + $_.Exception.Message) }
}

try {
    $reply = Invoke-RestMethod -Uri $StatusUrl -Method Get -Headers @{ 'X-AegisGuard-Token' = $Token } -TimeoutSec 15
} catch {
    return
}
# Only a real boolean true counts, not a string that merely reads as one.
if (($reply.uninstall -isnot [bool]) -or ($reply.uninstall -ne $true)) { return }

Step 'stop the screen agent' {
    Stop-ScheduledTask -TaskName $ScreenTask -ErrorAction SilentlyContinue
    Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -like "*$InstallDir*screen-agent.ps1*" } |
        ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
}
Step 'remove the screen agent task' {
    Unregister-ScheduledTask -TaskName $ScreenTask -Confirm:$false -ErrorAction SilentlyContinue
}
Step 'undo the lock settings left in the profiles of signed-in users' {
    Get-ChildItem Registry::HKEY_USERS -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^S-1-5-21-[\d-]+$' } | ForEach-Object {
        Remove-ItemProperty -Path ('Registry::' + $_.Name + '\Software\Microsoft\Windows\CurrentVersion\Policies\System') -Name DisableTaskMgr -ErrorAction SilentlyContinue
        Remove-Item -Path ('Registry::' + $_.Name + '\Software\AegisGuard') -Recurse -ErrorAction SilentlyContinue
    }
}
Step 'stop and uninstall the Wazuh agent' {
    Stop-Service -Name WazuhSvc -Force -ErrorAction SilentlyContinue
    $roots = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    $app = Get-ItemProperty -Path $roots -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like 'Wazuh Agent*' } | Select-Object -First 1
    if ($app -and $app.PSChildName -match '^\{') {
        Start-Process -FilePath msiexec.exe -ArgumentList ('/x ' + $app.PSChildName + ' /qn /norestart') -Wait
    } else {
        sc.exe delete WazuhSvc | Out-Null
    }
}
Step 'delete what the Wazuh agent left behind' {
    Remove-Item -Path (Join-Path ${env:ProgramFiles(x86)} 'ossec-agent') -Recurse -Force -ErrorAction SilentlyContinue
}
Step 'remove the Windows Defender exclusion' {
    Remove-MpPreference -ExclusionPath $InstallDir -ErrorAction SilentlyContinue
}
Step 'remove this check and the AegisGuard folder' {
    Unregister-ScheduledTask -TaskName $RemovalTask -Confirm:$false -ErrorAction SilentlyContinue
    # This very script is in that folder: delete it from another process once this one has ended.
    Start-Process -FilePath cmd.exe -ArgumentList ('/c ping 127.0.0.1 -n 6 >nul & rd /s /q "' + $InstallDir + '"') -WindowStyle Hidden
}
"""

# Runs once, elevated, from the installer: writes the removal check and registers
# it as a SYSTEM task. Separate from the screen agent setup so it can fail alone.
_SETUP_REMOVAL_CHECK = r"""$ErrorActionPreference = 'Stop'
# Best effort: monitoring works without this, so a failure here only warns.
try {
    [IO.File]::WriteAllBytes('__REMOVAL_PATH__', [Convert]::FromBase64String(__REMOVAL_B64__))
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "__REMOVAL_PATH__"'
    $triggers = @(
        (New-ScheduledTaskTrigger -AtStartup),
        (New-ScheduledTaskTrigger -Once -At ((Get-Date).AddMinutes(2)) -RepetitionInterval (New-TimeSpan -Minutes 5) -RepetitionDuration (New-TimeSpan -Days 3650))
    )
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 10) -MultipleInstances IgnoreNew
    Register-ScheduledTask -TaskName '__REMOVAL_TASK_NAME__' -Action $action -Trigger $triggers -Principal $principal -Settings $settings -Force | Out-Null
} catch {
    Write-Warning ('Automatic removal support could not be set up: ' + $_.Exception.Message)
}
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
echo    - remove AegisGuard from this computer again (it uninstalls
echo      itself when this employee account is deleted)
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
{screen_agent_set_lines}
{removal_agent_set_lines}
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
rem Renew the window: the download may have taken a while.
powershell -NoProfile -Command "try {{ Invoke-RestMethod -Uri $env:AG_MAINT_URL -Method Post -Headers @{{'X-AegisGuard-Token'=$env:AG_TOKEN}} -TimeoutSec 10 | Out-Null }} catch {{}}"
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
rem Lets the company remove AegisGuard again when it deletes this account. Best effort.
powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand {removal_setup_encoded}

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


def _env_chunks(prefix: str, text: str) -> tuple[str, str]:
    """cmd.exe refuses batch lines longer than 8191 characters (it aborts the
    whole script), so a script's Base64 is spread over several environment
    variables, PREFIX_00, PREFIX_01, ... Returns the `set` lines for the .cmd
    and the PowerShell expression that joins them back together."""
    b64 = base64.b64encode(text.encode("utf-8")).decode("ascii")
    chunks = [b64[i : i + _CMD_CHUNK] for i in range(0, len(b64), _CMD_CHUNK)]
    set_lines = "\n".join(f'set "{prefix}_{i:02d}={chunk}"' for i, chunk in enumerate(chunks))
    expr = "(" + " + ".join(f"$env:{prefix}_{i:02d}" for i in range(len(chunks))) + ")"
    return set_lines, expr


def build_installer(company: str, employee: str, key_line: str, screen_token: str) -> bytes:
    portal = settings.portal_public_url.rstrip("/")
    screen_agent = _SCREEN_AGENT.replace("__UPLOAD_URL__", portal + "/api/agent/screen").replace("__TOKEN__", screen_token)
    removal_agent = (
        _REMOVAL_AGENT.replace("__STATUS_URL__", portal + "/api/agent/status")
        .replace("__TOKEN__", screen_token)
        .replace("__INSTALL_DIR__", INSTALL_DIR)
        .replace("__TASK_NAME__", TASK_NAME)
        .replace("__REMOVAL_TASK_NAME__", REMOVAL_TASK_NAME)
    )
    agent_set_lines, agent_b64_expr = _env_chunks("AG_SCREEN_AGENT", screen_agent)
    removal_set_lines, removal_b64_expr = _env_chunks("AG_REMOVAL_AGENT", removal_agent)
    setup = (
        _SETUP_SCREEN_AGENT.replace("__INSTALL_DIR__", INSTALL_DIR)
        .replace("__AGENT_B64__", agent_b64_expr)
        .replace("__AGENT_PATH__", SCREEN_AGENT_PATH)
        .replace("__TASK_NAME__", TASK_NAME)
    )
    removal_setup = (
        _SETUP_REMOVAL_CHECK.replace("__REMOVAL_B64__", removal_b64_expr)
        .replace("__REMOVAL_PATH__", REMOVAL_AGENT_PATH)
        .replace("__REMOVAL_TASK_NAME__", REMOVAL_TASK_NAME)
    )
    script = _TEMPLATE.format(
        company=_comment_safe(company),
        employee=_comment_safe(employee),
        manager=settings.wazuh_manager_address,
        msi_url=settings.wazuh_agent_msi_url,
        key_line=key_line,
        maintenance_url=portal + "/api/agent/maintenance",
        screen_token=screen_token,
        install_dir=INSTALL_DIR,
        task_name=TASK_NAME,
        # Base64 keeps the multi-line scripts out of cmd.exe's quoting rules.
        screen_agent_set_lines=agent_set_lines,
        removal_agent_set_lines=removal_set_lines,
        setup_encoded=base64.b64encode(setup.encode("utf-16-le")).decode("ascii"),
        removal_setup_encoded=base64.b64encode(removal_setup.encode("utf-16-le")).decode("ascii"),
    )
    # cmd.exe expects CRLF line endings.
    return script.replace("\r\n", "\n").replace("\n", "\r\n").encode("ascii")
