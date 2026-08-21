# Accessible operational UI reference

Status: design input  
Retrieved: 2026-08-09

## Primary sources

- [W3C status messages](https://www.w3.org/WAI/WCAG21/Techniques/aria/ARIA22)
- [W3C non-text contrast](https://www.w3.org/WAI/WCAG22/Understanding/non-text-contrast)
- [GOV.UK status tags](https://design-system.service.gov.uk/components/tag/)
- [GOV.UK tabs](https://design-system.service.gov.uk/components/tabs/)
- [GOV.UK error messages](https://design-system.service.gov.uk/components/error-message/)
- [Material tooltips](https://m1.material.io/components/tooltips.html)
- [Material accessibility](https://m1.material.io/usability/accessibility.html)
- [Carbon progress indicators](https://preview.carbondesignsystem.com/building-blocks/core/components/progress-indicator/accessibility)

## Design consequences

- Use plain-language, sentence-case status labels. Keep machine codes in
  details, tooltips, or evidence records rather than making them the primary
  label.
- Never use color as the only status signal. Pair color with text, shape, and
  an accessible name.
- Essential explanations must be visible or reachable without hover. Tooltips
  are appropriate for short helper text, not for the only definition of a
  critical state.
- Tabs need clear labels, a visible active state, a heading in the selected
  panel, and a usable narrow-screen arrangement.
- An error or blocked state should say what happened and what safe next step is
  available; it should not expose secrets or imply that an unsafe action is
  available.
- Dynamic non-focus-taking status updates need a programmatic status role.

## Review questions

- Can a first-time operator explain the page without knowing Solvan's internal
  vocabulary?
- Does the screen remain understandable without color, hover, or animation?
- Is the most important information visible before technical provenance?
- Does every warning distinguish “needs attention” from “cannot proceed”?
- Does mobile layout preserve approval, target, evidence, and safety context?
