class Dispatcher {
  int Handle(int kind, Message msg) {
    switch (kind) {
      case 1:
        Record(msg);
      case 2:
        return Reject(msg);
      default:
        return Accept(msg);
    }
  }
}
