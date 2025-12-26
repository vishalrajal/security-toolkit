$env:PORT = "8082"
$p = Start-Process "go" -ArgumentList "run", "./cmd/webui" -WorkingDirectory "e:\subfinder" -NoNewWindow -PassThru
Start-Sleep -Seconds 10
echo "Sending request..."
try {
    $body = @{
        domain = "example.com"
        resolve_dns = $false
        port_scan = $false
        url_discovery = $true
    } | ConvertTo-Json
    
    $response = Invoke-RestMethod -Uri "http://localhost:8082/api/scan" -Method Post -Body $body -ContentType "application/json"
    $response | ConvertTo-Json -Depth 5
} catch {
    echo "Error: $_"
} finally {
    Stop-Process -Id $p.Id -Force
}
