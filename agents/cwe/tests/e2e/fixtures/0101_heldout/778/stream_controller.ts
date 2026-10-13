// Feature 0101 held-out (LLD 4.6), CWE-778 Concept A at the idiom level.
// A WHATWG stream source errors its controller: the consumer reading the stream
// receives the failure. Every identifier is invented.
// HELD-OUT-TOKENS: ReadableStream, controller

export function catalogueStream(pages: PageCursor) {
  return new ReadableStream({
    async pull(controller) {
      try {
        controller.enqueue(await pages.next());
      } catch (e) { // EXPECT: clean
        controller.error(e);
      }
    },
  });
}

export function decryptedStream(chunks: ChunkCursor, sessionKey: CryptoKey) {
  return new ReadableStream({
    async pull(controller) {
      try {
        controller.enqueue(await decryptChunk(sessionKey, await chunks.next()));
      } catch (e) { // EXPECT: finding
        controller.error(e);
      }
    },
  });
}
