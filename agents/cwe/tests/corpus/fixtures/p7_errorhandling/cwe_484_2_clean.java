public class Router {
  int route(int op, Request req) {
    switch (op) {
      case 1:
        audit(req);
        break;
      case 2:
        return deny(req);
      default:
        return allow(req);
    }
  }
}
