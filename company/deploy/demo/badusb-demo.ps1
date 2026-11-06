<#
  AegisGuard demo: behaves like a BadUSB device.

  A real BadUSB (a "Rubber Ducky") is a USB stick that Windows takes for a keyboard and that then types
  a script by itself, within seconds of being plugged in: Win+R, "cmd", Enter, and the commands.
  This script does the typing half, so that any ordinary USB keyboard becomes the demo device:

      1. it waits until a NEW USB keyboard shows up (you plug one in);
      2. a moment later it presses Win+R, types "cmd" and Enter, and types a harmless payload.

  Windows records the new keyboard (event 6416) and the command prompt that starts seconds later;
  AegisGuard puts the two together (services/badusb.py) and reports a BadUSB.

  The payload only runs whoami, hostname and echo. Nothing is downloaded, changed or deleted.

  USE IT ONLY ON THE DEMO VIRTUAL MACHINE, never on your own computer: it takes over the keyboard
  for a few seconds, typing into whatever window is in front.

  Usage (a normal PowerShell window in the VM, run as the signed-in user):
      .\badusb-demo.ps1                   wait for a new USB keyboard, then type
      .\badusb-demo.ps1 -Now              type at once (no keyboard is plugged in, so AegisGuard sees only an
                                          ordinary command prompt, not a BadUSB)
      .\badusb-demo.ps1 -DelaySeconds 1   how long after the keyboard appears the typing starts (default 2)

  Plugging a keyboard into a VM: VMware: VM > Removable Devices > (the keyboard) > Connect.
  VirtualBox: Devices > USB > (the keyboard). The device must be a USB keyboard, not the VM's own keyboard.
#>
param(
    [switch]$Now,
    [int]$DelaySeconds = 2,
    [string]$Payload = "whoami & hostname & echo AegisGuard BadUSB demo"
)

Add-Type -AssemblyName System.Windows.Forms
Add-Type @"
using System;
using System.Runtime.InteropServices;
public static class Keys {
    [DllImport("user32.dll")] public static extern void keybd_event(byte vk, byte scan, uint flags, UIntPtr extra);
    public static void Chord(byte modifier, byte key) {
        keybd_event(modifier, 0, 0, UIntPtr.Zero);
        keybd_event(key, 0, 0, UIntPtr.Zero);
        keybd_event(key, 0, 2, UIntPtr.Zero);
        keybd_event(modifier, 0, 2, UIntPtr.Zero);
    }
}
"@

function Get-KeyboardIds {
    @(Get-PnpDevice -Class Keyboard -PresentOnly -ErrorAction SilentlyContinue | ForEach-Object { $_.InstanceId })
}

if (-not $Now) {
    $known = Get-KeyboardIds
    Write-Host "Waiting for a new USB keyboard. Plug it in now (Ctrl+C to stop)..."
    do {
        Start-Sleep -Milliseconds 200
        $new = @(Get-KeyboardIds | Where-Object { $known -notcontains $_ })
    } until ($new.Count -gt 0)
    Write-Host ("New keyboard: " + ($new -join ", "))
}

Start-Sleep -Seconds $DelaySeconds
Write-Host "Typing..."

# Win+R opens the Run box, like the real device does.
[Keys]::Chord(0x5B, 0x52)          # left Windows key + R
Start-Sleep -Milliseconds 700
[System.Windows.Forms.SendKeys]::SendWait("cmd{ENTER}")
Start-Sleep -Milliseconds 900
# SendKeys treats + ^ % ~ ( ) { } [ ] as commands; wrap those in braces to type them as they are.
$text = [regex]::Replace($Payload, '[\+\^%~\(\)\{\}\[\]]', '{$0}')
[System.Windows.Forms.SendKeys]::SendWait($text + "{ENTER}")
Write-Host "Done. Check the portal's Security Logs for the USB keyboard and the BadUSB alert."
