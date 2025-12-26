const { app, BrowserWindow } = require('electron');
const path = require('path');
const { spawn } = require('child_process');
const http = require('http');

let mainWindow;
let backendProcess;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
    },
    // Modern frameless look suggestion - optional, sticking to standard for now but with dark theme
    backgroundColor: '#050816',
    show: false // Don't show until ready
  });

  // Hide menu bar
  mainWindow.setMenuBarVisibility(false);

  // Load the backend URL once it's ready
  checkBackendReady();

  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
  });

  mainWindow.on('closed', function () {
    mainWindow = null;
  });
}

function startBackend() {
  console.log('Starting backend...');
  // We'll run the existing webui command
  // Assuming 'go' is in path, or we can use the built binary if preferred.
  // Using 'go run ./cmd/webui' as per current setup for flexibility.
  // In a built app, we'd spawn the compiled binary.
  
  const cmd = 'go';
  const args = ['run', './cmd/webui']; // Adjust path if needed relative to where electron starts

  backendProcess = spawn(cmd, args, {
    cwd: __dirname, // Run from project root
    env: process.env,
    shell: true // Helpful for windows compatibility
  });

  backendProcess.stdout.on('data', (data) => {
    console.log(`Backend stdout: ${data}`);
  });

  backendProcess.stderr.on('data', (data) => {
    console.error(`Backend stderr: ${data}`);
  });

  backendProcess.on('close', (code) => {
    console.log(`Backend process exited with code ${code}`);
  });
}

function checkBackendReady() {
  const url = 'http://localhost:8080';
  
  const check = () => {
    http.get(url, (res) => {
      if (res.statusCode === 200) {
        console.log('Backend is ready!');
        mainWindow.loadURL(url);
      } else {
        // Retry if status is not 200 (though usually it either connects or fails)
        setTimeout(check, 1000); 
      }
    }).on('error', (err) => {
      // Backend not ready yet
      console.log('Waiting for backend...');
      setTimeout(check, 1000);
    });
  };

  check();
}

app.whenReady().then(() => {
  startBackend();
  createWindow();

  app.on('activate', function () {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', function () {
  if (process.platform !== 'darwin') app.quit();
});

app.on('will-quit', () => {
  // Kill web server process
  if (backendProcess) {
    // Basic kill
    // On Windows with shell:true, we might need a tree kill, but let's try standard first
    // For shell: true, we often need 'taskkill' on windows
    if (process.platform === 'win32') {
       spawn('taskkill', ['/pid', backendProcess.pid, '/f', '/t']);
    } else {
       backendProcess.kill();
    }
  }
});
