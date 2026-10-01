# Pushes the company portal from this Windows checkout to the Ubuntu server.
# Usage (from anywhere):
#   powershell -ExecutionPolicy Bypass -File "D:\CyberSecurity\Final Year Project\system_2.0\AegisGuard\company\deploy\deploy.ps1"
# You'll be asked for the Ubuntu password (scp, ssh, then sudo).

$ErrorActionPreference = "Stop"

$Server = "shuyang@192.168.241.87"
$Remote = "/opt/aegisguard/AegisGuard"
$Archive = Join-Path $env:TEMP "aegisguard-company.tar.gz"
$RepoParent = Resolve-Path (Join-Path $PSScriptRoot "..\..\..")

Write-Host "==> Packing company portal + resources"
Push-Location $RepoParent
try {
    tar -czf $Archive --exclude=.venv --exclude=__pycache__ --exclude=.env --exclude=.env.local-backup AegisGuard/company AegisGuard/resources
    if ($LASTEXITCODE -ne 0) { throw "tar failed" }
} finally {
    Pop-Location
}

Write-Host "==> Uploading"
scp $Archive "${Server}:/tmp/aegisguard-company.tar.gz"
if ($LASTEXITCODE -ne 0) { throw "scp failed" }

# Old app code is removed first so files deleted on Windows don't linger on
# the server; .venv and .env (server-only) are left untouched.
$RemoteCommand = @(
    "sudo rm -rf $Remote/company/frontend $Remote/company/backend/app $Remote/company/backend/alembic $Remote/company/deploy $Remote/resources",
    "sudo tar -xzf /tmp/aegisguard-company.tar.gz -C /opt/aegisguard",
    "sudo sed -i 's/\r$//' $Remote/company/deploy/remote-update.sh",
    "sudo bash $Remote/company/deploy/remote-update.sh",
    "rm -f /tmp/aegisguard-company.tar.gz"
) -join " && "

Write-Host "==> Updating server"
ssh -t $Server $RemoteCommand
if ($LASTEXITCODE -ne 0) { throw "Remote update failed (see output above)" }

Remove-Item $Archive
Write-Host "==> Done. Hard-refresh the portal in the browser (Ctrl+Shift+R)."
