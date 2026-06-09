# Final Testing Checklist

**Python & CLI:**
- [x] `pip install -e .`
- [x] `agilityshift scan ./examples/vulnerable-bank-api`
- [x] `agilityshift scan ./examples/vulnerable-bank-api --report all`
- [x] `agilityshift scan ./examples/vulnerable-bank-api --explain`
- [x] `agilityshift scan ./examples/vulnerable-bank-api --fail-on critical`
- [x] `pytest` (All passing)

**Reports:**
- [x] `agilityshift-report.json` generates correctly.
- [x] `agilityshift-report.html` generates correctly.
- [x] HTML opens cleanly in modern browsers.
- [x] JSON contains all severity mapping and findings.
- [x] Template explanations appear properly formatted.

**Dashboard:**
- [x] `cd dashboard`
- [x] `npm install`
- [x] `npm run dev`
- [x] Readiness score visual renders.
- [x] Findings table populates dynamically.
- [x] Detail panel reveals Code, Fix, and Explanations.
- [x] Hero warning banner appears.

**CI Gate:**
- [x] `--fail-on critical` returns exit code 1.
- [x] `--fail-on none` returns exit code 0.
