export function a(x: () => void) {
  try {
    x();
  } catch (e) {
    const closer = "}";
    logger.error("failed", e, closer);
  }
}

export function b(x: () => void) {
  try {
    x();
  } catch (e) { // a closing } inside this comment must not end the scope
    logger.error("failed", e);
  }
}
