// EXPECT-NEXT: clean  ws relay event e
socket.on('message', (e) => client.send(e))
