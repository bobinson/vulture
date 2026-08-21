window.addEventListener("message", (event) => {
  const payload = event.data;
  applyTheme(payload.theme);
});
