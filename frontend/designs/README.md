# Vulture designs

Design files for the frontend, drawn with the product's real tokens so a review of
a mockup is a review of what the implementation will render.

```
designs/
  tokens.css        the design system — single source of truth for colour, type, shape, layout
  components.css    primitives drawn only with tokens: what exists in the app + the 0093 report vocabulary
  NNNN-*.html       one design per feature, linking the two files above
  inline.py         builds a single self-contained HTML file for sharing (inlines the CSS)
```

## The one rule

**`tokens.css` and `src/index.css` `@theme` must agree.** `src/designs.parity.test.ts`
fails `vitest` if a token is added, removed or changed on one side only, if the
severity palette drifts, or if `components.css` uses a hex literal instead of a token.
Change a colour in both places, or the build tells you.

## Using the system

- **Designing**: start a new `NNNN-name.html` with
  `<link rel="stylesheet" href="tokens.css"><link rel="stylesheet" href="components.css">`
  and build with the `.v-*` classes. Open the file directly in a browser — no build.
- **Implementing**: the class names in `components.css` §3 are the vocabulary the React
  components are expected to expose (`v-tile`, `v-chip`, `v-row`, `v-seen`, `v-scan`…).
  Reuse a token before inventing a value; add a token to *both* files before using a new one.
- **Reviewing**: a design is approved when every colour, radius and type size in it
  resolves to a token. Anything else is a design decision that has not been made yet.

## Sharing a design

`python3 designs/inline.py designs/0093-unified-target-report.html > /tmp/0093.html`
produces one file with the CSS inlined. Fonts still load from Google Fonts.

## Designs

| file | feature | status |
|---|---|---|
| `0093-unified-target-report.html` | 0093 — one report per codebase; scans, filters, closures, drill-down | for review |
