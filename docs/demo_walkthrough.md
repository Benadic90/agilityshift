# Demo Walkthrough

**Step 1:** Show vulnerable code.
Open `examples/vulnerable-bank-api/src/auth/verify.js` and show the `Buffer.alloc(256)` limit.

**Step 2:** Run basic scan.
```bash
agilityshift scan ./examples/vulnerable-bank-api
```

**Step 3:** Run scan with reports.
```bash
agilityshift scan ./examples/vulnerable-bank-api --report all --explain
```

**Step 4:** Open HTML report.
Double-click `agilityshift-report.html` in your file explorer to show the standalone enterprise report.

**Step 5:** Open dashboard.
```bash
cd dashboard
npm install
npm run dev
```
Open `localhost:5173` in your browser to show the interactive visualizations.

**Step 6:** Run CI/CD fail command.
```bash
agilityshift scan ./examples/vulnerable-bank-api --fail-on critical
```
Show the "FAILED" response and exit code.

**Step 7:** Final explanation.
"Existing tools tell you where crypto is. AgilityShift tells you where post-quantum migration will break your code."
