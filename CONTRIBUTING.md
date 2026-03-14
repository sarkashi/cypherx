# Contributing to CypherX

Thank you for your interest in contributing!

## How to Contribute

**1. Fork the repository**
Click the Fork button on GitHub.

**2. Clone your fork**
```bash
git clone https://github.com/YOUR_USERNAME/cypherx
cd cypherx
```

**3. Create a branch**
```bash
git checkout -b feature/your-feature-name
```

**4. Make your changes**
Follow the code standards below.

**5. Commit**
```bash
git commit -m "Add: your feature description"
```

**6. Push and open a Pull Request**
```bash
git push origin feature/your-feature-name
```
Then open a Pull Request on GitHub.

---

## Code Standards

- Python 3.8+ compatible
- Zero comment lines in any .py file
- No hardcoded API keys
- All inputs must go through `core/security.py guard.sanitize()`
- Every module must work on both Linux and Windows
- Every command must have a `--limit` flag
- Output format: clean, minimal, professional

## What We Need

- New platform support in `modules/osint.py`
- New CVE entries in `modules/vuln.py`
- New subdomain wordlist entries
- Bug fixes
- Windows compatibility improvements
- Performance improvements

## Questions

Open an issue on GitHub or email: cypherx.dev@gmail.com
