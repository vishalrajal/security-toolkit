# Subfinder Web UI Startup Script
Write-Host "Starting Subfinder Web UI..." -ForegroundColor Cyan

# Check if Go is available
$goAvailable = $false
try {
    $goVersion = go version 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Go found: $goVersion" -ForegroundColor Green
        $goAvailable = $true
    }
} catch {
    Write-Host "Go not found in PATH" -ForegroundColor Yellow
}

if (-not $goAvailable) {
    Write-Host ""
    Write-Host "ERROR: Go is not installed or not in your PATH." -ForegroundColor Red
    Write-Host "Please install Go from https://golang.org/dl/ or add it to your PATH." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Alternatively, if you have Go installed elsewhere, you can:" -ForegroundColor Yellow
    Write-Host "1. Add Go's bin directory to your PATH" -ForegroundColor Yellow
    Write-Host "2. Or build the binary manually: go build -o subfinder.exe ./cmd/subfinder" -ForegroundColor Yellow
    Write-Host "   Then run: go run ./cmd/webui" -ForegroundColor Yellow
    exit 1
}

# Check if subfinder binary exists
if (-not (Test-Path "subfinder.exe") -and -not (Test-Path "subfinder")) {
    Write-Host "Building subfinder binary..." -ForegroundColor Yellow
    go build -o subfinder.exe ./cmd/subfinder
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Failed to build subfinder binary" -ForegroundColor Red
        exit 1
    }
    Write-Host "Subfinder binary built successfully!" -ForegroundColor Green
}

# Start the web server
Write-Host ""
Write-Host "Starting web server on http://localhost:8080" -ForegroundColor Cyan
Write-Host "Press Ctrl+C to stop the server" -ForegroundColor Yellow
Write-Host ""

go run ./cmd/webui

