// A token in the legacy session format. Its third segment decodes to readable
// text, not to a MAC or a signature, so no key signed it.
export const LEGACY_TOKEN =
  // EXPECT-NEXT: clean
  "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJsZWdhY3ktdXNlciJ9.bGVnYWN5LXNpZ25hdHVyZQ";
