window.addEventListener('error', (ev) => {
  // EXPECT-NEXT: clean  client beacon
  navigator.sendBeacon('/telemetry', ev.error.stack)
})
