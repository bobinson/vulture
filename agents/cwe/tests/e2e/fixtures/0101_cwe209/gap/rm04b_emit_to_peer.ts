export function onMsg2(socket: any) {
  socket.on('error', (err: Error) => {
    // EXPECT-NEXT: clean  known-gap emit to peer
    socket.emit('server_error', err.stack);
  });
}
