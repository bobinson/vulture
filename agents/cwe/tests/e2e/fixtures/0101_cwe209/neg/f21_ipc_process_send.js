try { work() } catch (err) {
  // EXPECT-NEXT: clean  ipc process send
  process.send({ type: 'failed', error: err.message })
}
