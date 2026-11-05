try { handle(msg) } catch (err) {
  // EXPECT-NEXT: clean  queue dlq
  channel.sendToQueue('dlq', Buffer.from(err.message))
}
