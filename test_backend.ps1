$env:PORT = "8081"
Start-Process "go" -ArgumentList "run", "./cmd/webui" -WorkingDirectory "e:\subfinder" -NoNewWindow
Start-Sleep -Seconds 10
echo "Sending request..."
curl.exe -X POST http://localhost:8081/api/scan -H "Content-Type: application/json" -d '{"domain": "example.com", "resolve_dns": false, "port_scan": false, "url_discovery": true}'
echo "Done."
