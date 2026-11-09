---
version: 1
slug: "home"
primary_target: "home"
related_targets: ["result","metrics","404"]
---

# Surface brief — PhishLens checker (home, result, metrics, 404)

Scope: the whole PhishLens web app. Visitor mode: Operate for the checker (home + result), Read for the metrics page.

Audience: IceHacks 2026 judges; anyone who received a suspicious link; the cousin's FYP examiners. Job: paste a link, get a verdict with reasons, in seconds. Proof/content: the live checker, the 29 named detectors, the trained model with SHAP reasons, the honest holdout metrics. Constraints: Django templates + one stylesheet; 512MB host; light, clean, professional (founder's taste); no invented claims; every number from measured holdout metrics; the URL is never visited.

## Direction contract

THESIS: PhishLens is the examiner's bench. The visitor brings a document — a link — they suspect is forged, and the page examines it in the open, circling each forgery in red pencil and writing the finding in the margin. It refuses the category default on both sides: the dark security dashboard with neon alerts, and the gentle cream tool page that hides its workings behind a soft verdict. The verdict is never a bare number; the evidence is the page.

OWN-WORLD: Pale cool-grey evidence paper ground, near-black ink, one red — the examiner's pencil red — doing the annotation and the danger state. Type: a precise system grotesque for the interface; monospace for the address itself and all data, because the URL is evidence and is set like evidence. Hairline rules instead of cards; findings listed as a flat evidence ledger with rule numbers (R01–R29) as exhibit references. Density precise and generous. The red pencil appears only where a finding exists, never as decoration. State colours sit on the same palette: dark green for Low, dark amber for Medium, the pencil red for High.

STORY: The visitor understands within seconds that this tool reads links the way a forensic examiner reads a document; believes the verdict because each reason is shown on the address itself, circled and annotated; and acts by pasting their own link. A judge sees the mechanism dramatized — the trick circled, the margin note explaining it — instead of being told about it.

FIRST VIEWPORT: A slim header — PhishLens wordmark left, Checker / How it works / Metrics right, one hairline below. Then the work area: the heading "Is this link a phish?" in the grotesque, a short lede, and the address field — a wide bordered input set in monospace with a solid ink Check button. Beneath it, the example link and the privacy note in dark, readable small text. Below, "How it works" as three ruled rows, not cards. The signature move lives on the result page: the checked URL displayed as Exhibit A, large in monospace, with each detected trick circled in red pencil and a numbered margin note naming it.

FORM: Forensic document lab, position 1 of 7 grounded directions (proofreader's desk 2, passport control 3, banknote / security print 4 — the roll's assignment — newspaper fact-check 5, customs declaration 6, lighthouse 7). The user chose this card over the assigned direction. seed:985b9651b6cafb9b.

FINISH: unreviewed and undocumented is unfinished; this build ends with the finish review, the verdict, DESIGN.md, and every shipping raster carrying its provenance.

## Unresolved decisions

- None open: the user picked the direction; the detector findings (contrast 2.4:1 on hint text, ~90ch step lines, 3px side-border on the advice box) are all fixed inside this build.
