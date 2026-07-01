const express = require("express");
// Safe: dotfiles denied and indexing disabled.
app.use("/files", express.static("/var/data", { dotfiles: "deny", index: false }));
