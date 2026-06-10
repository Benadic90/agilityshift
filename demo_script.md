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

## Minute 2:10 - 2:40 (Show Dashboard & Blast Radius Graph)
"We generated our enterprise reports. Let's look at the interactive dashboard."
*(Switch to browser running localhost:5173)*
"We instantly see a PQC Readiness Score of 0/100. Let's toggle over to the new **Blast Radius Graph**. Here you can visually see our target PQC profile in the center, and exactly which files and cryptographic assets are dangerously impacted. Red nodes mean critical migration risks."

## Minute 2:40 - 3:20 (Auto-Fix PR Generation)
"Now, catching the bugs is great, but fixing them is better. Let's use the new Auto-Fix engine."
*(Run in terminal)*:
```bash
agilityshift scan ./examples/vulnerable-python-api --report all --create-pr
```
"AgilityShift just ran the scan, intelligently rewrote the Python code to replace those hardcoded limits with dynamic PQC policies, created a new isolated git branch, and opened a Pull Request automatically. The developer doesn't even have to hunt for the fix."

## Minute 3:20 - 3:50 (CI/CD Gate)
"Finally, we need to stop these limits from ever hitting production again. Let's run it as a CI/CD failure gate."
*(Run in terminal)*:
```bash
agilityshift scan ./examples/vulnerable-python-api --fail-on critical
```
"We hit our threshold, and it exits with code 1. Deployment is blocked *before* a production failure."

## Minute 3:50 - 4:00 (Final Pitch)
"AgilityShift gives enterprises the power to prepare for post-quantum transitions safely. Existing tools tell you where crypto is. AgilityShift tells you where it breaks, and fixes it for you. Thank you."
