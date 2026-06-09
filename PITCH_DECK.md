# PITCH DECK

## Slide 1
**Title:** AgilityShift
**Subtitle:** Find PQC migration breakage before production fails.

## Slide 2
**Problem:**
Post-quantum migration is coming, but old apps have hidden size assumptions. Larger signatures and keys will shatter hardcoded constraints.

## Slide 3
**Why current tools are not enough:**
Most tools find crypto usage. They do not show where apps will break. AgilityShift focuses purely on structural limits.

## Slide 4
**Solution:**
AgilityShift scans code, database schemas, and API contracts to find exact file-line breakage risks, cross-referencing limits against formal PQC profiles like ML-DSA.

## Slide 5
**Demo:**
Vulnerable bank app → scanner → exact finding → HTML report/Dashboard → CI/CD failure gate.

## Slide 6
**Impact:**
Helps banks, fintech, SaaS, and digital infrastructure migrate safely and securely to quantum-safe cryptography without catastrophic downtime.
