# NightfallLX Universal Installer for Windows PowerShell
$ErrorActionPreference = "Stop"

Write-Host @"

  ███╗   ██╗██╗ ██████╗ ██╗  ██╗████████╗███████╗ █████╗ ██╗     ██╗     ██╗   ██╗
  ████╗  ██║██║██╔════╝ ██║  ██║╚══██╔══╝██╔════╝██╔══██╗██║     ██║     ╚██╗ ██╔╝
  ██╔██╗ ██║██║██║  ███╗███████║   ██║   █████╗  ███████║██║     ██║      ╚████╔╝ 
  ██║╚██╗██║██║██║   ██║██╔══██║   ██║   ██╔══╝  ██╔══██║██║     ██║      ██╔═██╗ 
  ██║ ╚████║██║╚██████╔╝██║  ██║   ██║   ██║     ██║  ██║███████╗███████╗██╔╝ ██╗
  ╚═╝  ╚═══╝╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝
  :: Next-Gen Web Assessment & Recon Suite :: [ Pure Go v2.0 Windows ] ::

"@ -ForegroundColor Cyan

# 1. Check Go compiler
if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
    Write-Host "[!] Error: Go compiler (golang) is not installed." -ForegroundColor Red
    Write-Host "    Please install Go 1.21+ from https://go.dev/dl/ and run this script again."
    Exit 1
}

Write-Host "[*] Compiling NightfallLX binary from source with optimizations..." -ForegroundColor Yellow
go build -ldflags="-s -w" -o nightfalllx.exe .
if ($LASTEXITCODE -ne 0) {
    Write-Host "[!] Build failed!" -ForegroundColor Red
    Exit 1
}

# 2. Determine target install directory
$targetDir = "$env:LOCALAPPDATA\Programs\NightfallLX"
if (-not (Test-Path $targetDir)) {
    New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
}

$destExe = Join-Path $targetDir "nightfalllx.exe"
Copy-Item -Path "nightfalllx.exe" -Destination $destExe -Force
Write-Host "[+] Binary installed to: $destExe" -ForegroundColor Green

# Also mirror to GOPATH\bin for instant global availability
$goPath = (go env GOPATH)
if ($goPath) {
    $goBin = Join-Path $goPath "bin"
    if (-not (Test-Path $goBin)) {
        New-Item -ItemType Directory -Path $goBin -Force | Out-Null
    }
    Copy-Item -Path "nightfalllx.exe" -Destination (Join-Path $goBin "nightfalllx.exe") -Force
    Write-Host "[+] Binary mirrored to: $(Join-Path $goBin 'nightfalllx.exe')" -ForegroundColor Green
}

# 3. Add to User PATH if not present
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
$pathParts = $userPath -split ";"
if ($pathParts -notcontains $targetDir) {
    $newUserPath = $userPath.TrimEnd(";") + ";$targetDir"
    [Environment]::SetEnvironmentVariable("Path", $newUserPath, "User")
    $env:Path += ";$targetDir"
    Write-Host "[+] Added $targetDir to User PATH environment variable." -ForegroundColor Green
}

Write-Host ""
Write-Host "[✓] NightfallLX is successfully installed globally!" -ForegroundColor Green
Write-Host "You can now run 'nightfalllx' from any CMD or PowerShell window!" -ForegroundColor Yellow
Write-Host ""
& $destExe -version
