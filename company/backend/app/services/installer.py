"""Builds the per-endpoint one-click Windows installer (.cmd).

Each file embeds that endpoint's own Wazuh agent key and screen-upload
token, so it's a credential: whoever runs it gets a computer enrolled as
this endpoint. It shows a monitoring notice that must be accepted, installs
the Wazuh agent, writes the key into client.keys (so no open self-enrollment
is needed), installs the screen agent as a hidden task that runs in each
user's session at logon (a Windows service can't capture the desktop), and
installs the scan agent, a SYSTEM task that reports USB drives and new
downloads (names, attributes and hashes only) for the portal to judge.
"""

import base64
import re

from app.core.config import settings

INSTALL_DIR = r"C:\Program Files\AegisGuard"
SCREEN_AGENT_PATH = INSTALL_DIR + r"\screen-agent.ps1"
TASK_NAME = "AegisGuard Screen Agent"
REMOVAL_TASK_NAME = "AegisGuard Removal Check"
REMOVAL_AGENT_PATH = INSTALL_DIR + r"\remove-agent.ps1"
SCAN_AGENT_PATH = INSTALL_DIR + r"\scan-agent.ps1"
SCAN_TASK_NAME = "AegisGuard Scan Agent"
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
    if ($sinceStatus -ge 2) {
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

# Runs as SYSTEM from startup, hidden, in a loop. It looks for a USB drive that has just been plugged in and
# for new files in the users' Downloads folders, and reports what it finds to the portal, which judges it
# (services/scan_results.py). It only reads: nothing is opened, run, changed, and no file content is sent,
# only names, attributes and hashes.
_SCAN_AGENT = r"""# AegisGuard scan agent. Reports to the portal; the portal decides what is bad.
$ErrorActionPreference = 'Continue'
$Url = '__SCAN_URL__'
$Token = '__TOKEN__'
$StateDir = Join-Path $env:ProgramData 'AegisGuard'
$StateFile = Join-Path $StateDir 'scan-state.txt'
$LogFile = Join-Path $StateDir 'scan.log'
# Programs, scripts, shortcuts, libraries and installers: what a USB worm is made of, and what is hashed.
$Programs = @('.exe', '.scr', '.com', '.pif', '.bat', '.cmd', '.vbs', '.vbe', '.js', '.jse', '.wsf', '.wsh', '.ps1', '.hta', '.cpl', '.msi', '.jar', '.lnk', '.dll')
# Hashed as well: archives and documents are what downloads are mostly made of.
$HashTypes = $Programs + @('.zip', '.rar', '.7z', '.iso', '.img', '.doc', '.docx', '.docm', '.xls', '.xlsx', '.xlsm', '.ppt', '.pptm', '.pdf', '.rtf')
$PartialTypes = @('.crdownload', '.part', '.tmp', '.download', '.opdownload')
$MaxHashBytes = 200MB
$MaxEntries = 4000
$DownloadsEvery = 60
$DrivePoll = 3

# What the agent did, for whoever has to find out why a drive was not reported (ProgramData\AegisGuard\scan.log).
function Write-Log([string]$Message) {
    try {
        New-Item -ItemType Directory -Force -Path $StateDir | Out-Null
        if ((Test-Path -LiteralPath $LogFile) -and ((Get-Item -LiteralPath $LogFile).Length -gt 1MB)) { Remove-Item -LiteralPath $LogFile -Force }
        Add-Content -LiteralPath $LogFile -Value ('[{0}] {1}' -f (Get-Date -Format 's'), $Message) -Encoding UTF8
    } catch {}
}

function Send-Scan($Body) {
    $json = $Body | ConvertTo-Json -Depth 6 -Compress
    $bytes = [Text.Encoding]::UTF8.GetBytes($json)
    $reply = Invoke-RestMethod -Uri $Url -Method Post -Body $bytes -ContentType 'application/json; charset=utf-8' -Headers @{ 'X-AegisGuard-Token' = $Token } -TimeoutSec 60
    Write-Log ('sent {0} scan of {1}: {2} entries, portal found {3}' -f $Body.kind, $Body.source, @($Body.files).Count, $reply.findings)
    return $reply
}

# Programs that must never be ended, whatever the portal says.
$Protected = @('system', 'registry', 'smss.exe', 'csrss.exe', 'wininit.exe', 'winlogon.exe', 'services.exe', 'lsass.exe', 'svchost.exe', 'explorer.exe', 'dwm.exe', 'fontdrvhost.exe')

# Containment, when the portal reports a Critical finding: end the processes that run from a place (a
# USB drive: their program or their command line is on it) or from exact files, and the processes they
# started. A lock keeps a person from the keyboard; it does not stop a script that is already running.
function Stop-FromLocation([string[]]$Prefixes, [string[]]$Files) {
    $all = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)
    $targets = @{}
    foreach ($p in $all) {
        if (($p.ProcessId -eq $PID) -or ($Protected -contains ([string]$p.Name).ToLower())) { continue }
        $path = [string]$p.ExecutablePath
        $cmd = [string]$p.CommandLine
        $hit = $false
        foreach ($x in $Prefixes) {
            if ($x -and ($path.StartsWith($x, [StringComparison]::OrdinalIgnoreCase) -or $cmd.IndexOf($x, [StringComparison]::OrdinalIgnoreCase) -ge 0)) { $hit = $true }
        }
        foreach ($f in $Files) { if ($f -and ($path -ieq $f)) { $hit = $true } }
        if ($hit) { $targets[[int]$p.ProcessId] = $p }
    }
    do {  # what those processes started
        $added = $false
        foreach ($p in $all) {
            if ($targets.ContainsKey([int]$p.ParentProcessId) -and -not $targets.ContainsKey([int]$p.ProcessId) -and ($p.ProcessId -ne $PID) -and -not ($Protected -contains ([string]$p.Name).ToLower())) {
                $targets[[int]$p.ProcessId] = $p
                $added = $true
            }
        }
    } while ($added)
    $ended = @()
    $failed = @()
    foreach ($id in $targets.Keys) {
        $p = $targets[$id]
        if (-not (Get-Process -Id $id -ErrorAction SilentlyContinue)) { continue }  # already gone (it ended with its parent)
        $line = ([string]$p.CommandLine)
        $record = [ordered]@{ name = [string]$p.Name; pid = [int]$id; command_line = $line.Substring(0, [Math]::Min(300, $line.Length)) }
        try {
            Stop-Process -Id $id -Force -ErrorAction Stop
            $ended += $record
            Write-Log ('containment: ended {0} (pid {1}) {2}' -f $p.Name, $id, $line.Substring(0, [Math]::Min(150, $line.Length)))
        } catch {
            $record.error = $_.Exception.Message.Substring(0, [Math]::Min(200, $_.Exception.Message.Length))
            $failed += $record
            Write-Log ('containment: could not end ' + $p.Name + ' (pid ' + $id + '): ' + $_.Exception.Message)
        }
    }
    return @{ Ended = $ended; Failed = $failed }
}

# Tells the portal what containment did (it becomes a "Containment" event in Security Logs).
function Send-Containment($ScanId, $Source, $Result) {
    $body = @{ scan_id = $ScanId; source = $Source; ended = @($Result.Ended); failed = @($Result.Failed) }
    $bytes = [Text.Encoding]::UTF8.GetBytes(($body | ConvertTo-Json -Depth 6 -Compress))
    Invoke-RestMethod -Uri ($Url -replace '/scan$', '/containment') -Method Post -Body $bytes -ContentType 'application/json; charset=utf-8' -Headers @{ 'X-AegisGuard-Token' = $Token } -TimeoutSec 30 | Out-Null
    Write-Log ('containment reported to the portal: {0} ended, {1} could not be ended' -f @($Result.Ended).Count, @($Result.Failed).Count)
}

function Get-Sha256($Path) {
    try { return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLower() } catch { return $null }
}

# What an autorun.inf starts, and whether those programs carry a valid digital signature
# (a Windows installation drive has an autorun.inf too, pointing at Microsoft's signed setup.exe).
function Get-AutorunInfo($Root, $File) {
    $lines = @()
    try {
        foreach ($l in (Get-Content -LiteralPath $File -TotalCount 100 -ErrorAction Stop)) {
            if ($l -match '^\s*(open|shellexecute|shell\\[^=]*\\command)\s*=\s*(.+)$') { $lines += $l.Trim() }
        }
    } catch {}
    $programs = @()
    foreach ($l in $lines) {
        $value = ($l -split '=', 2)[1].Trim().Trim('"')
        $words = $value -split ' '
        for ($n = $words.Count; $n -ge 1; $n--) {
            try {
                $candidate = Join-Path $Root (($words[0..($n - 1)] -join ' ').Trim('"'))
                if (Test-Path -LiteralPath $candidate -PathType Leaf) { $programs += $candidate; break }
            } catch {}
        }
    }
    $signed = $false
    if ($programs.Count -gt 0) {
        $signed = $true
        foreach ($p in $programs) {
            try { if ([string](Get-AuthenticodeSignature -LiteralPath $p).Status -ne 'Valid') { $signed = $false } } catch { $signed = $false }
        }
    }
    return @{ Target = ($lines -join '; '); Signed = $signed }
}

# The part of a drive's file list that the rules look at: programs, scripts, shortcuts and libraries,
# hidden files and folders, and autorun.inf. The SHA256 of the programs, where shortcuts lead.
function Get-DriveListing($Drive) {
    $root = (Get-Item -LiteralPath ($Drive + '\') -Force).FullName.TrimEnd('\')
    $shell = New-Object -ComObject WScript.Shell
    $entries = New-Object System.Collections.ArrayList
    $total = 0
    foreach ($it in (Get-ChildItem -LiteralPath ($root + '\') -Recurse -Force -ErrorAction SilentlyContinue)) {
        $rel = $it.FullName.Substring($root.Length).TrimStart('\')
        if ($rel -match '^(System Volume Information|\$RECYCLE\.BIN)(\\|$)') { continue }
        $total++
        if ($entries.Count -ge $MaxEntries) { continue }
        $hidden = (([int]$it.Attributes -band 6) -ne 0)  # Hidden or System
        if ($it.PSIsContainer) {
            if ($hidden) { [void]$entries.Add([ordered]@{ path = $rel; is_dir = $true; size = 0; hidden = $true; sha256 = $null; target = $null; target_signed = $null }) }
            continue
        }
        $ext = $it.Extension.ToLower()
        $isAutorun = ($it.Name -ieq 'autorun.inf') -and ($it.DirectoryName.TrimEnd('\') -eq $root)
        if (-not ($hidden -or ($Programs -contains $ext) -or $isAutorun)) { continue }
        $entry = [ordered]@{ path = $rel; is_dir = $false; size = [long]$it.Length; hidden = $hidden; sha256 = $null; target = $null; target_signed = $null }
        if (($HashTypes -contains $ext) -and ($it.Length -le $MaxHashBytes)) { $entry.sha256 = Get-Sha256 $it.FullName }
        if ($ext -eq '.lnk') {
            try { $l = $shell.CreateShortcut($it.FullName); $entry.target = ("$($l.TargetPath) $($l.Arguments)").Trim() } catch {}
        }
        if ($isAutorun) {
            $info = Get-AutorunInfo $root $it.FullName
            $entry.target = $info.Target
            $entry.target_signed = $info.Signed
        }
        [void]$entries.Add($entry)
    }
    return @{ Total = $total; Files = $entries }
}

# Letters of USB drives: flash drives (removable) and USB disks.
function Get-UsbDrives {
    $letters = @()
    try { Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=2' -ErrorAction Stop | ForEach-Object { $letters += $_.DeviceID } } catch {}
    try {
        Get-Disk -ErrorAction Stop | Where-Object { $_.BusType -eq 'USB' } | Get-Partition -ErrorAction SilentlyContinue |
            Where-Object { $_.DriveLetter } | ForEach-Object { $letters += ([string]$_.DriveLetter + ':') }
    } catch {}
    # A USB device can present itself as a CD drive: Windows still runs AutoRun for those (Microsoft, 2009),
    # so a drive of that kind is the one to look at most.
    try {
        Get-CimInstance Win32_CDROMDrive -ErrorAction Stop | Where-Object { $_.PNPDeviceID -like 'USBSTOR*' -and $_.Drive } | ForEach-Object { $letters += $_.Drive }
    } catch {}
    return @($letters | Sort-Object -Unique)
}

function Scan-Drive($Drive) {
    $label = ''
    try { $label = (Get-Volume -DriveLetter $Drive.Substring(0, 1) -ErrorAction Stop).FileSystemLabel } catch {}
    $listing = Get-DriveListing $Drive
    $scanId = [guid]::NewGuid().ToString('N')
    $source = ($Drive + ' (' + $label + ')')
    $reply = Send-Scan @{ scan_id = $scanId; kind = 'usb'; source = $source; total = $listing.Total; files = @($listing.Files) }
    if ($reply.contain) {
        $result = Stop-FromLocation @(($Drive + '\')) @()
        try { Send-Containment $scanId $source $result } catch { Write-Log ('containment report not sent: ' + $_.Exception.Message) }
    }
}

function Get-DownloadFolders {
    @(Get-ChildItem 'C:\Users' -Directory -Force -ErrorAction SilentlyContinue | ForEach-Object { Join-Path $_.FullName 'Downloads' } | Where-Object { Test-Path -LiteralPath $_ })
}

function Get-FileKey($f) { return ($f.FullName + '|' + $f.LastWriteTimeUtc.Ticks + '|' + $f.Length) }

# New files in Downloads, not yet reported. The first time the agent runs, what is already there is
# only remembered, not reported.
function Scan-Downloads($Seen, [bool]$Baseline) {
    $now = [DateTime]::UtcNow
    $new = @()
    foreach ($folder in (Get-DownloadFolders)) {
        foreach ($f in (Get-ChildItem -LiteralPath $folder -File -Recurse -Depth 1 -Force -ErrorAction SilentlyContinue)) {
            $key = Get-FileKey $f
            if ($Seen.ContainsKey($key)) { continue }
            if ($PartialTypes -contains $f.Extension.ToLower()) { continue }
            if (($now - $f.LastWriteTimeUtc).TotalSeconds -lt 10) { continue }  # still being written
            if ($Baseline) { $Seen[$key] = $true; continue }
            $new += , @($f, $key)
        }
    }
    if ($Baseline -or $new.Count -eq 0) { return }
    for ($i = 0; $i -lt $new.Count; $i += 100) {
        $batch = $new[$i..([Math]::Min($i + 99, $new.Count - 1))]
        $files = @()
        foreach ($pair in $batch) {
            $f = $pair[0]
            $ext = $f.Extension.ToLower()
            $sha = $null
            if (($HashTypes -contains $ext) -and ($f.Length -le $MaxHashBytes)) { $sha = Get-Sha256 $f.FullName }
            $files += [ordered]@{ path = $f.FullName; is_dir = $false; size = [long]$f.Length; hidden = $false; sha256 = $sha; target = $null; target_signed = $null }
        }
        try {
            $scanId = [guid]::NewGuid().ToString('N')
            $reply = Send-Scan @{ scan_id = $scanId; kind = 'download'; source = 'Downloads'; total = $new.Count; files = @($files) }
            foreach ($pair in $batch) { $Seen[$pair[1]] = $true }
            if ($reply.contain) {
                $result = Stop-FromLocation @() @($reply.contain_paths)
                try { Send-Containment $scanId 'Downloads' $result } catch { Write-Log ('containment report not sent: ' + $_.Exception.Message) }
            }
        } catch { Write-Log ('downloads not sent, will retry: ' + $_.Exception.Message) }  # not remembered: tried again next time
    }
}

function Save-State($Seen) {
    try {
        New-Item -ItemType Directory -Force -Path $StateDir | Out-Null
        Set-Content -LiteralPath $StateFile -Value @($Seen.Keys) -Encoding UTF8
    } catch {}
}

# --- main loop ---
# Dot-sourcing this file (to test its functions) does not start it.
if ($MyInvocation.InvocationName -ne '.') {
    Write-Log 'scan agent started'
    $seen = @{}
    $baseline = -not (Test-Path -LiteralPath $StateFile)
    if (-not $baseline) { foreach ($line in (Get-Content -LiteralPath $StateFile -Encoding UTF8 -ErrorAction SilentlyContinue)) { if ($line) { $seen[$line] = $true } } }
    $scanned = @{}
    $retryAfter = @{}
    $sinceDownloads = $DownloadsEvery
    while ($true) {
        $present = Get-UsbDrives
        foreach ($drive in @($scanned.Keys)) { if ($present -notcontains $drive) { $scanned.Remove($drive) } }  # unplugged: scanned again next time
        foreach ($drive in @($retryAfter.Keys)) { if ($present -notcontains $drive) { $retryAfter.Remove($drive) } }
        foreach ($drive in $present) {
            if ($scanned.ContainsKey($drive) -or -not (Test-Path -LiteralPath ($drive + '\'))) { continue }
            if ($retryAfter.ContainsKey($drive) -and ([DateTime]::UtcNow -lt $retryAfter[$drive])) { continue }
            Write-Log ('USB drive ' + $drive + ' found')
            try {
                Scan-Drive $drive
                $scanned[$drive] = $true
                $retryAfter.Remove($drive)
            } catch {
                # not ready or the portal cannot be reached: try again in a minute, not every few seconds (a scan reads the whole drive)
                $retryAfter[$drive] = [DateTime]::UtcNow.AddSeconds(60)
                Write-Log ('scan of ' + $drive + ' failed, will retry in 60 s: ' + $_.Exception.Message)
            }
        }
        if ($sinceDownloads -ge $DownloadsEvery) {
            $sinceDownloads = 0
            Scan-Downloads $seen $baseline
            $baseline = $false
            Save-State $seen
        }
        Start-Sleep -Seconds $DrivePoll
        $sinceDownloads += $DrivePoll
    }
}
"""

# Runs once, elevated, from the installer: writes the scan agent and starts it as a SYSTEM task at startup.
# Separate from the other setups so that it can fail alone: monitoring works without it.
_SETUP_SCAN_AGENT = r"""$ErrorActionPreference = 'Stop'
try {
    New-Item -ItemType Directory -Force -Path '__INSTALL_DIR__' | Out-Null
    [IO.File]::WriteAllBytes('__SCAN_PATH__', [Convert]::FromBase64String(__SCAN_B64__))
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "__SCAN_PATH__"'
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
    Register-ScheduledTask -TaskName '__SCAN_TASK_NAME__' -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
    # On a re-install the running agent keeps its old token in memory: stop it, so the new one reads the new token.
    Stop-ScheduledTask -TaskName '__SCAN_TASK_NAME__' -ErrorAction SilentlyContinue
    Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -like '*__SCAN_PATH__*' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    Start-ScheduledTask -TaskName '__SCAN_TASK_NAME__'
} catch {
    Write-Warning ('The USB and download scan could not be set up: ' + $_.Exception.Message)
}
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
$ScanTask = '__SCAN_TASK_NAME__'
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
Step 'stop and remove the USB and download scan' {
    Stop-ScheduledTask -TaskName $ScanTask -ErrorAction SilentlyContinue
    Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -like "*$InstallDir*scan-agent.ps1*" } |
        ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    Unregister-ScheduledTask -TaskName $ScanTask -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item -Path (Join-Path $env:ProgramData 'AegisGuard') -Recurse -Force -ErrorAction SilentlyContinue
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
echo    - check USB drives that are plugged in, and newly downloaded
echo      files, for malware (it reads file names and fingerprints;
echo      the files themselves are not sent anywhere)
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
rem Event 6416 (a new external device was recognised) feeds the BadUSB check: a USB keyboard
rem followed within seconds by a command prompt is a device that types commands.
auditpol /set /subcategory:"{{0CCE9248-69AE-11D9-BED3-505054503030}}" /success:enable >nul 2>&1
rem Include the command line in 4688 events (e.g. "powershell -enc ...").
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f >nul 2>&1

rem Log what is typed into PowerShell (event 4104), and have the Wazuh agent
rem send that channel, so commands that start no program of their own (Get-Process,
rem Get-LocalUser, ...) are seen too. Best effort, and only added once.
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f >nul 2>&1
powershell -NoProfile -Command "try {{ $f = $env:AGENT_DIR + '\ossec.conf'; $c = [IO.File]::ReadAllText($f); if ($c -notmatch 'PowerShell/Operational') {{ $b = '<localfile><location>Microsoft-Windows-PowerShell/Operational</location><log_format>eventchannel</log_format><query>Event/System[EventID=4104]</query></localfile>'; $i = $c.LastIndexOf('</ossec_config>'); [IO.File]::WriteAllText($f, $c.Insert($i, $b + [char]10)); }} }} catch {{}}" >nul 2>&1
net stop WazuhSvc >nul 2>&1
net start WazuhSvc >nul 2>&1

echo [6/6] Setting up the live screen view...
rem Defender would block the screen component, so exclude its folder first.
rem If Windows Tamper Protection refuses, the manual steps are shown at the end.
powershell -NoProfile -Command "try {{ Add-MpPreference -ExclusionPath '{install_dir}' }} catch {{}}" >nul 2>&1
powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand {setup_encoded}
if %errorlevel% neq 0 goto fail
{screen_agent_clear_lines}
rem Lets the company remove AegisGuard again when it deletes this account. Best effort.
powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand {removal_setup_encoded}
{removal_agent_clear_lines}
rem Checks USB drives that are plugged in and new downloads for malware. Best effort, and its
rem script is only put in the environment now, since the environment has a size limit.
{scan_agent_set_lines}
powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand {scan_setup_encoded}
{scan_agent_clear_lines}

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


def _clear_lines(set_lines: str) -> str:
    """`set "NAME="` for every variable `set_lines` sets: an empty value removes it, which frees the
    environment (Windows keeps all of it, at most about 32 KB, for every program started)."""
    return "\n".join(f'set "{name}="' for name in re.findall(r'^set "(\w+)=', set_lines, flags=re.M))


def build_installer(company: str, employee: str, key_line: str, screen_token: str) -> bytes:
    portal = settings.portal_public_url.rstrip("/")
    screen_agent = _SCREEN_AGENT.replace("__UPLOAD_URL__", portal + "/api/agent/screen").replace("__TOKEN__", screen_token)
    removal_agent = (
        _REMOVAL_AGENT.replace("__STATUS_URL__", portal + "/api/agent/status")
        .replace("__TOKEN__", screen_token)
        .replace("__INSTALL_DIR__", INSTALL_DIR)
        .replace("__TASK_NAME__", TASK_NAME)
        .replace("__SCAN_TASK_NAME__", SCAN_TASK_NAME)
        .replace("__REMOVAL_TASK_NAME__", REMOVAL_TASK_NAME)
    )
    scan_agent = _SCAN_AGENT.replace("__SCAN_URL__", portal + "/api/agent/scan").replace("__TOKEN__", screen_token)
    agent_set_lines, agent_b64_expr = _env_chunks("AG_SCREEN_AGENT", screen_agent)
    removal_set_lines, removal_b64_expr = _env_chunks("AG_REMOVAL_AGENT", removal_agent)
    scan_set_lines, scan_b64_expr = _env_chunks("AG_SCAN_AGENT", scan_agent)
    scan_setup = (
        _SETUP_SCAN_AGENT.replace("__INSTALL_DIR__", INSTALL_DIR)
        .replace("__SCAN_B64__", scan_b64_expr)
        .replace("__SCAN_PATH__", SCAN_AGENT_PATH)
        .replace("__SCAN_TASK_NAME__", SCAN_TASK_NAME)
    )
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
        scan_agent_set_lines=scan_set_lines,
        screen_agent_clear_lines=_clear_lines(agent_set_lines),
        removal_agent_clear_lines=_clear_lines(removal_set_lines),
        scan_agent_clear_lines=_clear_lines(scan_set_lines),
        setup_encoded=base64.b64encode(setup.encode("utf-16-le")).decode("ascii"),
        removal_setup_encoded=base64.b64encode(removal_setup.encode("utf-16-le")).decode("ascii"),
        scan_setup_encoded=base64.b64encode(scan_setup.encode("utf-16-le")).decode("ascii"),
    )
    # cmd.exe expects CRLF line endings.
    return script.replace("\r\n", "\n").replace("\n", "\r\n").encode("ascii")
