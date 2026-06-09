# Hackathon Demo Script: AgilityShift
**Duration**: 4 Minutes

---

## Minute 0:00 - 0:30 (Problem)
"Post-quantum cryptography migration is coming. The industry is focused on changing algorithms, but old applications have tiny, hidden limits. When we swap in post-quantum signatures—which are massive—our apps will crash. Existing tools tell you where crypto is. AgilityShift tells you where post-quantum migration will break your code."

## Minute 0:30 - 1:10 (Show Vulnerable App)
"Let's look at a standard vulnerable bank app. Here in JS, we have `Buffer.alloc(256)`. In our SQL schema, we have `signature VARCHAR(256)`. In our OpenAPI contract, `maxLength: 256`. These are ticking time bombs for migration."

## Minute 1:10 - 2:10 (Run Scanner)
"Let's run the AgilityShift scanner locally."
*(Run in terminal)*:
```bash
agilityshift scan ./examples/vulnerable-bank-api --report all --explain
```
"Look at this. It found exactly the file and line. It shows the current limit of 256 bytes, compares it against the ML-DSA-65 post-quantum standard, and reveals a 12.93x overflow ratio. It assigns a Critical severity, suggests a dynamic buffer fix, and generates a security explanation—all entirely offline."

## Minute 2:10 - 3:00 (Show Dashboard)
"We generated our enterprise reports. Let's look at the interactive dashboard."
*(Switch to browser running localhost:5173)*
"We instantly see a PQC Readiness Score of 0/100. We can see our severity breakdown, filter the findings table, and click on a finding to review the exact Code block, Developer Guidance, and Manager Summary."

## Minute 3:00 - 3:40 (CI/CD Gate)
"But we need to stop these from hitting production. Let's run it as a CI/CD failure gate."
*(Run in terminal)*:
```bash
agilityshift scan ./examples/vulnerable-bank-api --fail-on critical
```
"We hit our threshold, and it exits with code 1. Deployment is blocked *before* a production failure."

## Minute 3:40 - 4:00 (Final Pitch)
"AgilityShift gives banks, fintechs, and SaaS companies the power to prepare for post-quantum transitions safely. Existing tools tell you where crypto is. AgilityShift tells you where post-quantum migration will break your code. Thank you."
