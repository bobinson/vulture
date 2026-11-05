export function Note({ code }) {
  return <p>Don't {eval(code)}</p>; // EXPECT: finding
}
