# Go Installation Helper Script for Windows
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Go Installation Helper" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check if Go is already installed
try {
    $goVersion = go version 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[OK] Go is already installed!" -ForegroundColor Green
        Write-Host "  $goVersion" -ForegroundColor Gray
        Write-Host ""
        Write-Host "You can now run: .\start-webui.ps1" -ForegroundColor Yellow
        exit 0
    }
} catch {
    # Go not found, continue with installation guide
}

Write-Host "Go is not installed or not in your PATH." -ForegroundColor Yellow
Write-Host ""

# Check for package managers
$chocoAvailable = $false
$scoopAvailable = $false

try {
    $null = choco --version 2>&1
    if ($LASTEXITCODE -eq 0) {
        $chocoAvailable = $true
        Write-Host "[OK] Chocolatey detected" -ForegroundColor Green
    }
} catch {
    # Chocolatey not available
}

try {
    $null = scoop --version 2>&1
    if ($LASTEXITCODE -eq 0) {
        $scoopAvailable = $true
        Write-Host "[OK] Scoop detected" -ForegroundColor Green
    }
} catch {
    # Scoop not available
}

Write-Host ""
Write-Host "Installation Options:" -ForegroundColor Cyan
Write-Host ""

if ($chocoAvailable) {
    Write-Host "Option 1: Install via Chocolatey (Easiest)" -ForegroundColor Yellow
    Write-Host "  Run: choco install golang" -ForegroundColor White
    Write-Host ""
}

if ($scoopAvailable) {
    Write-Host "Option 2: Install via Scoop" -ForegroundColor Yellow
    Write-Host "  Run: scoop install go" -ForegroundColor White
    Write-Host ""
}

Write-Host "Option 3: Manual Installation (Recommended)" -ForegroundColor Yellow
Write-Host "  1. Visit: https://go.dev/dl/" -ForegroundColor White
Write-Host "  2. Download the Windows installer (.msi)" -ForegroundColor White
Write-Host "  3. Run the installer" -ForegroundColor White
Write-Host "  4. Restart your terminal" -ForegroundColor White
Write-Host ""

Write-Host "After installation, verify with: go version" -ForegroundColor Cyan
Write-Host ""

# Offer to open the download page
$response = Read-Host "Would you like to open the Go download page in your browser? (Y/N)"
if ($response -eq 'Y' -or $response -eq 'y') {
    Start-Process "https://go.dev/dl/"
    Write-Host "Download page opened!" -ForegroundColor Green
}

