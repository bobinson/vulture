function createWindow() {
  const win = new BrowserWindow({
    webPreferences: { nodeIntegration: false, contextIsolation: true },
  });
  win.loadFile("index.html");
  return win;
}
