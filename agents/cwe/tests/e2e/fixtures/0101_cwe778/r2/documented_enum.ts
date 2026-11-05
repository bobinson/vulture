// Feature 0101, CWE-778 Concept B: a conventionally documented status enum.
// Doc comments do not count toward the bounded enum-body scan, so members far
// below the `enum` line are still read as outcome NAMES (R778-6).

export enum ResponseStatus {
  /**
   * The 100 response status.
   */
  Continue = 100,
  /**
   * The 101 response status.
   */
  SwitchingProtocols = 101,
  /**
   * The 102 response status.
   */
  Processing = 102,
  /**
   * The 103 response status.
   */
  EarlyHints = 103,
  /**
   * The 200 response status.
   */
  Ok = 200,
  /**
   * The 201 response status.
   */
  Created = 201,
  /**
   * The 202 response status.
   */
  Accepted = 202,
  /**
   * The 204 response status.
   */
  NoContent = 204,
  /**
   * The 205 response status.
   */
  ResetContent = 205,
  /**
   * The 206 response status.
   */
  PartialContent = 206,
  /**
   * The 300 response status.
   */
  MultipleChoices = 300,
  /**
   * The 301 response status.
   */
  MovedPermanently = 301,
  /**
   * The 302 response status.
   */
  Found = 302,
  /**
   * The 303 response status.
   */
  SeeOther = 303,
  /**
   * The 304 response status.
   */
  NotModified = 304,
  /**
   * The 307 response status.
   */
  TemporaryRedirect = 307,
  /**
   * The 308 response status.
   */
  PermanentRedirect = 308,
  /**
   * The 400 response status.
   */
  BadRequest = 400,
  /**
   * The 401 response status.
   */
  Unauthorized = 401, // EXPECT: clean check=cwe.insufficient_logging.auth_decision
  /**
   * The 402 response status.
   */
  PaymentRequired = 402,
  /**
   * The 403 response status.
   */
  Forbidden = 403, // EXPECT: clean check=cwe.insufficient_logging.auth_decision
  /**
   * The 404 response status.
   */
  NotFound = 404,
  /**
   * The 405 response status.
   */
  MethodNotAllowed = 405,
  /**
   * The 406 response status.
   */
  NotAcceptable = 406,
  /**
   * The 408 response status.
   */
  RequestTimeout = 408,
  /**
   * The 409 response status.
   */
  Conflict = 409,
  /**
   * The 410 response status.
   */
  Gone = 410,
}
