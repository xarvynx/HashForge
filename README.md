# 🔐 HASHFORGE

A professional-grade password strength analysis tool that evaluates password security using advanced metrics, entropy calculations, and pattern detection. Built with a **FastAPI backend** for high-performance API responses.

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Python](https://img.shields.io/badge/Python-3.9%2B-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.109%2B-teal)

---

## 📖 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Tech Stack](#-tech-stack)
- [Architecture](#-architecture)
- [Getting Started](#-getting-started)
- [Project Structure](#-project-structure)
- [How It Works](#-how-it-works)
- [API Reference](#-api-reference)
- [Strength Scoring](#-strength-scoring)
- [Security & Privacy](#-security--privacy)
- [Roadmap](#-roadmap)
- [Contributing](#-contributing)
- [License](#-license)
- [Author](#-author)

---

## 🎯 Overview

**Password Strength Analyzer** is a backend service designed to help users create and evaluate strong passwords. Unlike basic checkers that only count characters, this tool performs deep analysis including:

- **Entropy calculation** (bits of randomness) — Shannon entropy: `E = L × log₂(R)`
- **Pattern detection** — dictionary words, keyboard walks, sequences, repeating patterns, leetspeak, years
- **Crack time estimation** — online throttled, offline slow/fast hash, GPU cluster
- **Breach checking** — HaveIBeenPwned API with k-anonymity model
- **Real-time feedback** — actionable suggestions for improvement
- **Secure generation** — cryptographically random passwords, passphrases, and PINs

---

## ✨ Features

### Core Features

- ✅ Entropy-based scoring (0–100 scale)
- ✅ Crack time estimation (online, offline, GPU attacks)
- ✅ Pattern & dictionary detection (Trie-optimized O(L) lookup)
- ✅ Common password blacklist check (top 10k breached passwords)
- ✅ Character composition breakdown
- ✅ Actionable improvement suggestions
- ✅ Password generator (cryptographically secure via `secrets` module)
- ✅ Passphrase generator (Diceware-style, memorable)
- ✅ PIN generator (numeric)

### Advanced Features

- 🔒 HaveIBeenPwned API integration (k-anonymity — only first 5 SHA-1 chars sent)
- 📊 Detailed metrics dashboard (entropy, composition, crack times)
- 🧠 Custom scoring algorithm (no third-party dependencies)
- ⚡ Fast API responses (<1ms analysis, <100ms with breach check)
- 📚 Auto-generated OpenAPI/Swagger docs at `/docs`

---

## 🛠 Tech Stack

| Layer | Technology | Purpose |
|-------|------------|---------|
| Backend | Python 3.9+ | Core analysis engine |
| Backend | FastAPI | High-performance async REST API framework |
| Backend | requests | HIBP breach API calls |
| Backend | hashlib | SHA-1 hashing for breach checks |
| Data | SecLists / english-words | Common passwords & dictionary wordlists |

---

## 🏗 Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    CLIENT (Any)                          │
│  ┌───────────────────────────────────────────────────┐  │
│  │  Browser / CLI / Mobile / Custom Integration       │  │
│  └───────────────────────────────────────────────────┘  │
└──────────────────────────┬──────────────────────────────┘
                           │  HTTP / JSON
                           ▼
┌─────────────────────────────────────────────────────────┐
│                  SERVER (Python FastAPI)                 │
│  ┌───────────────────────────────────────────────────┐  │
│  │  /api/analyze  │  /api/generate  │  /api/breach-check│  │
│  │  /api/generate/passphrase  │  /api/generate/pin   │  │
│  │  /api/health                                    │  │
│  └───────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────┐  │
│  │  Entropy Engine │ Pattern Detector (Trie) │ Scorer │  │
│  └───────────────────────────────────────────────────┘  │
└──────────────────────────┬──────────────────────────────┘
                           │
                           ▼
              ┌──────────────────────────┐
              │  External APIs / Data    │
              │  (HIBP, wordlists)       │
              └──────────────────────────┘
```

---

## 🚀 Getting Started

### Prerequisites

- **Python** 3.9+ — [Download](https://www.python.org/downloads/)
- **pip** — Python package manager
- **Git** — [Download](https://git-scm.com/)

### Installation

**1. Clone the repository:**

```bash
git clone https://github.com/xarvynx/HashForge
cd HashForge
```

**2. Create a virtual environment:**

```bash
python -m venv venv
```

**3. Activate the virtual environment:**

Windows:
```bash
venv\Scripts\activate
```

macOS / Linux:
```bash
source venv/bin/activate
```

**4. Install Python dependencies:**

```bash
pip install -r backend/requirements.txt
```

### Running the Application

**1. Start the FastAPI backend:**

```bash
cd backend
python app.py
# OR: uvicorn app:app --reload --port 5000
```

The server will start at `http://127.0.0.1:5000`.

**2. Access API documentation:**

- Swagger UI: `http://127.0.0.1:5000/docs`
- ReDoc: `http://127.0.0.1:5000/redoc`

**3. Test the API:**

```bash
# Analyze a password
curl -X POST http://127.0.0.1:5000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"password": "Test123!", "check_breach": false}'

# Generate a secure password
curl -X POST http://127.0.0.1:5000/api/generate \
  -H "Content-Type: application/json" \
  -d '{"length": 20, "use_symbols": true, "use_digits": true, "use_uppercase": true}'

# Check breach status
curl -X POST http://127.0.0.1:5000/api/breach-check \
  -H "Content-Type: application/json" \
  -d '{"password": "password123"}'
```

---

## 📁 Project Structure

```
HashForge/
│
├── backend/
│   ├── app.py                  # FastAPI application entry point
│   ├── analyzer.py             # Core password analysis orchestrator
│   ├── entropy.py              # Shannon entropy + crack time estimation
│   ├── patterns.py             # Pattern detection (Trie-optimized)
│   ├── breach_check.py         # HIBP k-anonymity integration
│   ├── generator.py            # Secure password/passphrase/PIN generator
│   ├── constants.py            # Wordlists, charsets, keyboard layouts
│   ├── requirements.txt        # Python dependencies
│   ├── test_backend.py         # Comprehensive test suite (35 tests)
│   └── data/
│       ├── common_passwords.txt    # Top 10k breached passwords
│       └── dictionary_words.txt    # 356k dictionary words
│
├── LICENSE
├── README.md
└── .gitignore
```

---

## 🧠 How It Works

### Analysis Pipeline

The server receives a password via HTTPS POST and runs the analysis pipeline:

1. **Character set detection** — identifies lowercase, uppercase, digits, symbols
2. **Length calculation** — measures raw length
3. **Entropy estimation** — `E = L × log₂(R)` where `L` = length, `R` = pool size
4. **Pattern detection** — checks for:
   - Dictionary words (Trie-based O(L) substring search)
   - Keyboard walks (precomputed sequences)
   - Alphabetic/numeric sequences
   - Repeating characters & patterns
   - Leetspeak substitutions (precompiled regex)
   - Years (1900-2029)
5. **Breach check** — SHA-1 hashes password, queries HIBP using k-anonymity
6. **Scoring** — weighted combination of all factors (0–100)
7. **Crack time estimation** — simulates attacks at various guess rates

### Scoring Formula

| Factor | Weight | Description |
|--------|--------|-------------|
| Length | 30% | Max at 20+ chars |
| Entropy | 30% | Max at 80+ bits |
| Character Variety | 20% | 5 pts each: lower, upper, digit, symbol |
| Pattern Penalty | −25% | Deductions for weak patterns (capped) |
| Breach Penalty | −50% | Massive penalty if breached |

---

## 🔌 API Reference

### POST /api/analyze

Analyzes a password's strength.

**Request:**
```json
{
  "password": "MyP@ssw0rd123",
  "check_breach": true
}
```

**Response:**
```json
{
  "score": 78,
  "strength": "Strong",
  "entropy": 72.4,
  "crack_time": {
    "online_throttled": "3 centuries",
    "offline_slow_hash": "5 years",
    "offline_fast_hash": "2 hours",
    "gpu_cluster": "12 seconds"
  },
  "feedback": {
    "warning": "Contains common word 'password'",
    "suggestions": [
      "Avoid dictionary words",
      "Add more unique characters",
      "Consider using a passphrase"
    ]
  },
  "breached": false,
  "composition": {
    "length": 13,
    "lowercase": true,
    "uppercase": true,
    "digits": true,
    "symbols": true
  }
}
```

### POST /api/generate

Generates a cryptographically secure random password.

**Request:**
```json
{
  "length": 20,
  "use_symbols": true,
  "use_digits": true,
  "use_uppercase": true,
  "exclude_ambiguous": false
}
```

**Response:**
```json
{
  "password": "x7#Kp9$mQ2!vL8@nR4&z",
  "entropy": 131.2,
  "length": 20,
  "composition": {
    "lowercase": true,
    "uppercase": true,
    "digits": true,
    "symbols": true
  }
}
```

### POST /api/generate/passphrase

Generates a Diceware-style memorable passphrase.

**Request:**
```json
{
  "word_count": 4,
  "separator": "-",
  "capitalize": false,
  "include_number": false
}
```

**Response:**
```json
{
  "password": "correct-horse-battery-staple",
  "entropy": 52.3,
  "length": 28,
  "composition": { ... }
}
```

### POST /api/generate/pin

Generates a numeric PIN.

**Request:** `POST /api/generate/pin?length=6`

**Response:**
```json
{
  "password": "482910",
  "entropy": 19.9,
  "length": 6,
  "composition": {
    "lowercase": false,
    "uppercase": false,
    "digits": true,
    "symbols": false
  }
}
```

### POST /api/breach-check

Checks if a password has been breached using HIBP k-anonymity API.

**Request:**
```json
{ "password": "password123" }
```

**Response:**
```json
{
  "breached": true,
  "count": 2266543
}
```

### GET /api/health

Health check endpoint.

**Response:**
```json
{
  "status": "healthy",
  "version": "1.0.0"
}
```

---

## 📊 Strength Scoring

### Weighted Formula

| Factor | Weight | Description |
|--------|--------|-------------|
| Length | 30% | Longer passwords score higher (max at 20 chars) |
| Entropy | 30% | Bits of randomness (max at 80 bits) |
| Character Variety | 20% | Mix of character types (5 pts each) |
| Pattern Penalty | −25% | Deductions for weak patterns (capped at 25) |
| Breach Penalty | −50% | Massive penalty if found in breaches |

### Score Interpretation

| Score | Strength | Color | Meaning |
|-------|----------|-------|---------|
| 0–20 | Very Weak | Red | Instantly crackable |
| 21–40 | Weak | Orange | Vulnerable to basic attacks |
| 41–60 | Fair | Yellow | Moderate protection |
| 61–80 | Strong | Green | Good for most uses |
| 81–100 | Very Strong | Blue | Excellent security |

---

## 🔒 Security & Privacy

- ✅ Passwords are **never stored** — not in databases, logs, or memory beyond the request
- ✅ HTTPS-only in production
- ✅ **k-anonymity** for breach checks — only first 5 SHA-1 hash chars sent to HIBP
- ✅ No third-party analytics on password inputs
- ✅ CORS configured for allowed origins (configure for production)
- ✅ Cryptographically secure generation via Python's `secrets` module

> ⚠️ **Note:** This tool is for educational and personal use. For production applications, always use established libraries like `zxcvbn` and follow [OWASP password guidelines](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html).

---

## 🗺 Roadmap

- [x] Core strength analysis engine
- [x] HIBP breach check integration (k-anonymity)
- [x] Secure password generator (cryptographically random)
- [x] Passphrase generator (Diceware-style)
- [x] PIN generator
- [x] Comprehensive test suite (35 tests)
- [x] Trie-optimized dictionary detection (<1ms)
- [ ] Browser extension
- [ ] CLI tool
- [ ] Multi-language support (i18n)
- [ ] Docker deployment
- [ ] Unit test coverage >90%

---

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

## 👤 Author

- GitHub: [https://github.com/xarvynx](https://github.com/xarvynx)
- Github: [https://github.com/youcefzwawcha-dev](https://github.com/youcefzwawcha-dev)
---

## 🙏 Acknowledgments

- [HaveIBeenPwned](https://haveibeenpwned.com/) for the breach API
- [OWASP](https://owasp.org/) for password security guidelines
- [NIST SP 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html) for password standards
- [SecLists](https://github.com/danielmiessler/SecLists) for common password lists
- [english-words](https://github.com/dwyl/english-words) for dictionary words
- The open-source community for inspiration and tools

---

<div align="center">

**⭐ If you found this project helpful, please give it a star! ⭐**

Made with ❤️ and ☕

</div>
