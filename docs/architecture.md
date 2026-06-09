# Architecture

**Input:**
Developer repository

**Pipeline:**
`RepoLoader` (Filters and indexes supported repository files)
↓
`JavaScript detector` (Analyzes JS/TS AST-lite patterns for Buffer allocs and length constraints)
`SQL detector` (Analyzes SQL DDL for VARCHAR/BLOB byte constraints on crypto columns)
`API schema detector` (Analyzes OpenAPI YAML/JSON for maxLength bounds)
↓
`PQC profile engine` (Injects required byte bounds based on target, e.g. ML-DSA)
↓
`Risk scoring engine` (Calculates severity and overall readiness penalty)
↓
`Suggested fix engine` (Attaches code remediation templates)
↓
`Template explanation engine` (Contextualizes the breach into human-readable guidance)
↓
`Reports` (Generates JSON and HTML artifacts)
`Dashboard` (Visualizes the data locally)
`CI/CD gate` (Returns sys exits to block deployments)

```text
+-----------------------+
|  Developer Repo (FS)  |
+-----------+-----------+
            |
            v
     +------+------+
     | RepoLoader  |
     +------+------+
            |
    +-------+-------+
    |   Detectors   |
    | (JS, SQL, API)|
    +-------+-------+
            |
   +--------+--------+
   | PQC Profile Eng |
   +--------+--------+
            |
   +--------+--------+
   |  Risk Scoring   |
   +--------+--------+
            |
   +--------+--------+
   | Fix & Explainer |
   +--------+--------+
            |
  +---------+---------+
  |                   |
  v                   v
Reports             CI Gate
 (HTML/JSON)         (Exit 1)
  |
  v
Dashboard
```
