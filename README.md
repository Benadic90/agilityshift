<div align="center">
  
  # 🚀 AgilityShift
  
  **Find where post-quantum cryptography migration will break your code before production fails.**

  [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
  [![React](https://img.shields.io/badge/React-18.x-blue)](https://reactjs.org/)
  [![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/)
  [![PQC Ready](https://img.shields.io/badge/PQC-Migration_Ready-success)](#)

  > *"Existing tools tell you where crypto is. AgilityShift tells you where post-quantum migration will break your code—and then fixes it for you."*

  **Created with ❤️ by Benadic**

</div>

---

## 🌌 The Problem: Y2Q is Coming
Post-quantum migration is coming. As organizations prepare for quantum-safe cryptography, they must transition to algorithms like `ML-DSA`. 

However, legacy applications have **hidden size assumptions**—such as `Buffer.alloc(256)`, `VARCHAR(256)`, or `maxLength: 256`—that implicitly expect tiny RSA or ECDSA artifacts. When you swap in massive Post-Quantum signatures, your application will silently truncate data, corrupt databases, and crash in production.

## 🛠️ The Solution: AgilityShift
AgilityShift acts as a pre-migration safety scanner and automated remediation engine. 

It deeply analyzes source code, database schemas, and API contracts to highlight exactly where your architecture will shatter, calculates overflow ratios against formal PQC profiles, and **automatically generates Pull Requests** to fix them.

---

## ✨ Why It's "Wonderful" (Key Features)

### 📊 Executive Blast Radius Graph
Don't just look at tables. AgilityShift parses your Cryptography Bill of Materials (CBOM) and renders a physics-based, interactive 2D network graph showing exactly which files and variables are at critical risk of breaking.

### 🤖 Auto-Fix PR Generation
AgilityShift doesn't just find the bug; it fixes it. The core engine dynamically rewrites your vulnerable code to use safe, policy-driven configurations, isolates it in a new branch, and seamlessly opens a GitHub Pull Request (`gh`). 

### 🧠 Local AI Explanations via Ollama
We use local-first LLMs (like `qwen2.5-coder`) to generate deep, contextual security explanations and manager summaries—without your code ever leaving your machine.

### 🛡️ Enterprise DevSecOps Native
Built for CI/CD. It exports to `SARIF` natively for **GitHub Advanced Security**, generates CycloneDX-inspired `CBOM` json files, and can block deployments as a strict CI/CD failure gate.

### 🔍 Advanced AST Detection
Uses native Abstract Syntax Tree (AST) parsing for languages like Python and JS to eliminate false positives and find the real constraints.

---

## ⚡ Interactive Quick Start

Get AgilityShift running locally in under 60 seconds!

### 1. Install the Core Engine
```bash
# Clone the repository
git clone https://github.com/Benadic90/agilityshift.git
cd agilityshift

# Install the CLI
pip install -e .
```

### 2. Run the Auto-Fix Scanner!
Watch the magic happen. Scan the vulnerable Python example, generate all enterprise reports, and trigger the Auto-Fix PR engine:

```bash
agilityshift scan ./examples/vulnerable-python-api --report all --create-pr
```

### 3. Launch the Interactive Dashboard & Blast Radius Graph
Boot up the visual triage system:

```bash
cd dashboard
npm install
npm run dev
```
🌐 Open `http://localhost:5173` in your browser. Click **"Blast Radius Graph"** to interact with your codebase!

### 4. Test the CI/CD Gate
Prove it works in a pipeline by setting a strict failure threshold:
```bash
agilityshift scan ./examples/vulnerable-python-api --fail-on critical
```

---

## 📁 Architecture Flow

1. **CLI Engine** parses files using AST/Regex against PQC Profiles (e.g. `ML-DSA-65`).
2. **AI Layer** passes findings to a local Ollama instance for context extraction.
3. **Report Generator** syncs findings to `JSON`, `HTML`, `SARIF`, and `CBOM`.
4. **Auto-Fixer** applies remediations and triggers Git/GH CLI commands.
5. **React Frontend** polls the reports and renders visual components and network graphs.

---

## 🔒 Security and Privacy Model
- **Local-first scanning**: Your code never leaves your machine. No cloud API calls are required to scan or evaluate risk.
- **CI/CD native**: The engine runs securely inside your private build environment.

---

## 👨‍💻 Author
**Benadic**  
Passionate about cryptography, DevSecOps, and making the post-quantum transition safe and seamless for everyone.

## 📄 License
This project is licensed under the MIT License.
