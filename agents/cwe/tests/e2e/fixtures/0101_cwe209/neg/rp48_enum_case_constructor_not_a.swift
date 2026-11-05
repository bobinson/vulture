func finish(_ state: CaptureState) {
    do {
        try state.writer.finish()
    } catch {
        // EXPECT-NEXT: clean  enum case constructor not a peer write
        state.fault = CaptureFault.writeFailed(error.localizedDescription)
    }
}
