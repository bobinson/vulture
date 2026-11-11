const { makePreview } = require("../lib/previews");

function attach(io) {
  io.on("connection", (socket) => {
    socket.on("preview", (msg) => {
      makePreview(msg.name);
      socket.emit("preview:done", msg.name);
    });
  });
}

module.exports = { attach };
