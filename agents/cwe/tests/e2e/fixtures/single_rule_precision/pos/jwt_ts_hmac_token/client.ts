// A service token signed with HS256: a 32-byte MAC from a real key.
export const SERVICE_TOKEN =
  // EXPECT-NEXT: finding
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzdmMtcmVwb3J0aW5nIiwic2NvcGUiOiJyZXBvcnRzOnJlYWQifQ.CPT5eycNG6Mald5szHduXuDHfcal7FArrinHkngyuOs";
// The widely published HS256 token: a well-formed token with a 32-byte MAC.
export const PUBLISHED =
  // EXPECT-NEXT: finding
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
