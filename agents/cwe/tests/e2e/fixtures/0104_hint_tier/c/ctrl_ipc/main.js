const { ipcMain } = require("electron");
const fs = require("fs");

ipcMain.handle("exists", (_e, filePath) => fs.existsSync(filePath)); // EXPECT: finding check=cwe.input_validation.path_traversal
