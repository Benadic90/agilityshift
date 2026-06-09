# Final Sanity Check

Run these commands prior to demo freeze to ensure total stability.

```bash
# Test Core
pip install -e .
pytest

# Test Workflows
agilityshift scan ./examples/vulnerable-bank-api --report all --explain
agilityshift scan ./examples/vulnerable-bank-api --fail-on none
agilityshift scan ./examples/vulnerable-bank-api --fail-on critical

# Test UI
cd dashboard
npm install
npm run build
```
