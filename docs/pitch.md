# Pitch

**Problem:**
Organizations know they need to migrate to Post-Quantum Cryptography (PQC), but they don't know where their systems will break. Existing tools only tell you where cryptography is used, not where hardcoded limits (like `VARCHAR(256)` or `Buffer.alloc(256)`) will fail when PQC introduces larger keys and signatures.

**Solution:**
AgilityShift is a local-first PQC migration breakage scanner. It analyzes source code, database schemas, and API contracts to pinpoint the exact file and line limits that conflict with upcoming PQC standards.

**Impact:**
Prevents catastrophic production failures during PQC migration. Saves thousands of hours of manual code review.

**Final Pitch:**
“Existing tools tell you where crypto is. AgilityShift tells you where post-quantum migration will break your code.”
