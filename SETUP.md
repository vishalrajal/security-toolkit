# Subfinder Web UI - Setup Guide

## Prerequisites

You need **Go** (Golang) installed to build and run the Subfinder Web UI.

## Installing Go on Windows

### Option 1: Download from Official Website (Recommended)

1. Visit https://go.dev/dl/
2. Download the Windows installer (`.msi` file) for the latest version
3. Run the installer and follow the instructions
4. The installer will automatically add Go to your PATH

### Option 2: Using Chocolatey (if you have it)

```powershell
choco install golang
```

### Option 3: Using Scoop (if you have it)

```powershell
scoop install go
```

## Verify Installation

After installing Go, open a **new** PowerShell window and run:

```powershell
go version
```

You should see output like: `go version go1.21.x windows/amd64`

## Building and Running the Web UI

Once Go is installed:

1. **Build the subfinder binary:**
   ```powershell
   go build -o subfinder.exe ./cmd/subfinder
   ```

2. **Start the web server:**
   ```powershell
   go run ./cmd/webui
   ```

   Or use the startup script:
   ```powershell
   .\start-webui.ps1
   ```

3. **Open your browser:**
   Navigate to http://localhost:8080

## Troubleshooting

### "go: command not found"
- Make sure Go is installed
- Restart your terminal/PowerShell after installing Go
- Verify Go is in your PATH: `$env:PATH` should contain the Go bin directory

### "subfinder binary not found"
- Make sure you've built the subfinder binary first: `go build -o subfinder.exe ./cmd/subfinder`
- The binary should be in the project root directory

### Port 8080 already in use
- Change the port by setting the PORT environment variable:
  ```powershell
   $env:PORT="8081"
   go run ./cmd/webui
   ```

