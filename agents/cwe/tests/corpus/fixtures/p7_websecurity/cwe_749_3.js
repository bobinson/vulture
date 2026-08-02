function createWindow() {
  const win = new BrowserWindow({
    webPreferences: { nodeIntegration: true, contextIsolation: false },
  });
  win.loadFile("index.html");
  return win;
}
