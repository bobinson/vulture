export function attach(socket: any) {
  const send = (frame: any) => socket.push(JSON.stringify(frame));
  const respond = (id: string, ok: boolean, payload: any) => send({ id, ok, payload });
  socket.onFrame(async (frame: any) => {
    try {
      respond(frame.id, true, await dispatch(frame));
    } catch (err) {
      send({ id: frame.id, ok: false, error: String(err) }); // EXPECT: clean gap-K13-frame
    }
  });
}
