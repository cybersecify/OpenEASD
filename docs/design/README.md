# Design docs

Product-design reference material for OpenEASD.

## `OpenEASD_UX_Flow.pdf` / `.html`

A 6-page UX-flow reference for product design — the core user journey, the three
result lenses (scan / findings / assets), the full screen inventory, the two
usage modes (interactive vs. monitoring), the UX design principles, the current
visual palette, live screenshots of the asset-centric screens, and a set of open
questions where design input adds the most value.

Describes the **v2.2.0** experience as a baseline. It is a UX *reference*, not a
spec — the flows are the live product; the "open questions" are invitations.

`.html` is the editable source (screenshots are base64-embedded, so it is
self-contained). To regenerate the PDF after editing the HTML, render it with
headless Chrome (no extra system libs needed):

```bash
"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
  --headless=new --disable-gpu --no-pdf-header-footer \
  --print-to-pdf=docs/design/OpenEASD_UX_Flow.pdf \
  "file://$(pwd)/docs/design/OpenEASD_UX_Flow.html"
```

(WeasyPrint — the app's own PDF engine — also works where its pango/cairo system
libs are installed, e.g. CI/Linux.)
