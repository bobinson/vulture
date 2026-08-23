window.onmessage = (event: MessageEvent) => {
  const command = event.data.command;
  execute(command);
};
