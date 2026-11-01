// pins: a callback registered with on() receives its payload-named parameter (data) as a network source (R-A)
bus.on("message", (data) => {
  fs.readFile("/srv/docs/" + data.file, () => {});
});
