const fs = require("fs");

module.exports = function attach(io) {
  io.on("connection", (socket) => {
    socket.on("exists", (filePath, ack) => ack(fs.existsSync(filePath))); // EXPECT: finding check=cwe.input_validation.path_traversal
  });
};
