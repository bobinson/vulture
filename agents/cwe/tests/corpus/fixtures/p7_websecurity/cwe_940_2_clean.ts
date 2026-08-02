window.onmessage = (event: MessageEvent) => {
  if (event.origin !== TRUSTED_ORIGIN) return;
  execute(event.data.command);
};
