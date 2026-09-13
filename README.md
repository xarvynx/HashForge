# 🔐 Password Strength Analyzer

A professional-grade password strength analysis tool that evaluates password security using advanced metrics, entropy calculations, and pattern detection. Built with a modern web interface and powered by a Python backend.

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Python](https://img.shields.io/badge/Python-3.9%2B-blue)
![JavaScript](https://img.shields.io/badge/JavaScript-ES6%2B-yellow)
![HTML5](https://img.shields.io/badge/HTML-5-orange)
![CSS3](https://img.shields.io/badge/CSS-3-blue)

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

**Password Strength Analyzer** is a full-stack application designed to help users create and evaluate strong passwords. Unlike basic checkers that only count characters, this tool performs deep analysis including:

- **Entropy calculation** (bits of randomness)
- **Pattern detection** (dictionary words, keyboard walks, sequences)
- **Crack time estimation** using modern GPU speeds
- **Breach checking** against known compromised passwords
- **Real-time feedback** with actionable suggestions

The project combines a sleek **HTML/CSS/JS frontend** with a robust **Python backend** for heavy computation and breach database lookups.

---

## ✨ Features

### Core Features

- ✅ Real-time password analysis as you type
- ✅ Entropy-based scoring (0–100 scale)
- ✅ Crack time estimation (online, offline, GPU attacks)
- ✅ Pattern & dictionary detection
- ✅ Common password blacklist check
- ✅ Character composition breakdown
- ✅ Actionable improvement suggestions
- ✅ Password generator (cryptographically secure)
- ✅ Copy-to-clipboard functionality

### Advanced Features

- 🔒 HaveIBeenPwned API integration (k-anonymity model)
- 📊 Detailed metrics dashboard
- 🎨 Modern, responsive UI with dark/light mode
- 🧠 Custom scoring algorithm (no third-party dependencies)
- ⚡ Fast API responses (<100ms)

---

## 🛠 Tech Stack

| Layer | Technology | Purpose |
|-------|------------|---------|
| Frontend | HTML5 | Semantic structure |
| Frontend | CSS3 | Responsive styling, animations |
| Frontend | JavaScript (ES6+) | Client-side logic, real-time feedback |
| Backend | Python 3.9+ | Core analysis engine |
| Backend | Flask / FastAPI | REST API framework |
| Backend | zxcvbn (optional) | Advanced pattern matching |
| Backend | requests | Breach API calls |
| Backend | hashlib | SHA-1 hashing for breach checks |

---

## 🏗 Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     CLIENT (Browser)                     │
│  ┌───────────────────────────────────────────────────┐  │
│  │  HTML  │  CSS  │  JavaScript (real-time UI)       │  │
│  └───────────────────────────────────────────────────┘  │
└──────────────────────────┬──────────────────────────────┘
                           │  HTTP / JSON
                           ▼
┌─────────────────────────────────────────────────────────┐
│                  SERVER (Python Flask)                   │
│  ┌───────────────────────────────────────────────────┐  │
│  │  /analyze  │  /generate  │  /breach-check         │  │
│  └───────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────┐  │
│  │  Entropy Engine │ Pattern Detector │ Scorer       │  │
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

Make sure you have the following installed:

- **Python** 3.9+ — [Download](https://www.python.org/downloads/)
- **pip** — Python package manager
- **Git** — [Download](https://git-scm.com/)
- A modern web browser (Chrome, Firefox, Edge, Safari)

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
pip install -r requirements.txt
```

**5. Configure environment variables (optional):**

Create a `.env` file in the root directory:

```env
FLASK_ENV=development
FLASK_DEBUG=True
PORT=5000
HIBP_API_ENABLED=true
```

### Running the Application

**1. Start the Python backend:**

```bash
python app.py
```

The server will start at `http://127.0.0.1:5000`.

**2. Open the frontend:**

- Open `index.html` in your browser, **or**
- Navigate to `http://127.0.0.1:5000` if Flask serves static files.

**3. Start analyzing passwords!** 🎉

---

## 📁 Project Structure

```
HashForge/
│
├── backend/
│   ├── app.py                  # Flask application entry point
│   ├── analyzer.py             # Core password analysis logic
│   ├── entropy.py              # Entropy calculation module
│   ├── patterns.py             # Pattern detection
│   ├── breach_check.py         # HIBP integration
│   ├── generator.py            # Secure password generator
│   ├── constants.py            # Common passwords, dictionaries
│   └── requirements.txt        # Python dependencies
│
├── frontend/
│   ├── index.html              # Main HTML page
│   ├── css/
│   │   ├── style.css           # Main stylesheet
│   │   └── theme.css           # Dark/light mode themes
│   ├── js/
│   │   ├── main.js             # Entry point
│   │   ├── api.js              # Backend API calls
│   │   ├── ui.js               # DOM manipulation
│   │   ├── meter.js            # Strength meter visualization
│   │   └── utils.js            # Helper functions
│   └── assets/
│       └── icons/              # SVG icons
│
├── tests/
│   ├── test_analyzer.py
│   ├── test_entropy.py
│   └── test_api.py
│
├── docs/
│   └── scoring.md              # Scoring algorithm documentation
│
├── .env.example
├── .gitignore
├── LICENSE
├── README.md
└── requirements.txt
```

---

## 🧠 How It Works

### Client-side (JavaScript)

- Captures user input in real time (debounced for performance)
- Sends password securely to the backend via `fetch()` POST request
- Displays strength meter, entropy score, and suggestions dynamically
- Never stores or logs the password

### Server-side (Python)

The server receives the password via HTTPS POST and runs the analysis pipeline:

1. **Character set detection** — identifies lowercase, uppercase, digits, symbols
2. **Length calculation** — measures raw length
3. **Entropy estimation** — `E = L × log₂(R)` where `L` = length, `R` = pool size
4. **Pattern detection** — checks for dictionary words, repeating characters, sequences, keyboard walks, and leetspeak substitutions
5. **Breach check** — SHA-1 hashes the password, queries HIBP API using k-anonymity
6. **Scoring** — combines all factors into a 0–100 score
7. **Crack time estimation** — simulates attacks at 10B guesses/sec (GPU)

The server returns a JSON response with score, feedback, and suggestions.

---

## 🔌 API Reference

### POST /api/analyze

Analyzes a password's strength.

**Request:**

```json
{
  "password": "MyP@ssw0rd123"
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

Generates a secure random password.

**Request:**

```json
{
  "length": 20,
  "use_symbols": true,
  "use_digits": true,
  "use_uppercase": true
}
```

**Response:**

```json
{
  "password": "x7#Kp9$mQ2!vL8@nR4&z",
  "entropy": 131.2
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

The overall score (0–100) is calculated using a weighted formula:

| Factor | Weight | Description |
|--------|--------|-------------|
| Length | 30% | Longer passwords score higher |
| Entropy | 30% | Bits of randomness |
| Character Variety | 20% | Mix of character types |
| Pattern Penalty | −25% | Deductions for weak patterns |
| Breach Penalty | −50% | Massive penalty if breached |

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

We take privacy seriously:

- ✅ Passwords are never stored — not in databases, logs, or memory beyond the request
- ✅ HTTPS-only in production
- ✅ k-anonymity for breach checks — only the first 5 characters of the SHA-1 hash are sent to HIBP
- ✅ No third-party analytics on password inputs
- ✅ Rate limiting to prevent abuse
- ✅ CORS configured for allowed origins only

> ⚠️ **Note:** This tool is for educational and personal use. For production applications, always use established libraries like `zxcvbn` and follow [OWASP password guidelines](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html).

---

## 🗺 Roadmap

- [x] Core strength analysis engine
- [x] Real-time frontend feedback
- [x] HIBP breach check integration
- [x] Password generator
- [ ] Passphrase generator (Diceware)
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

- GitHub: [https://github.com/youcefzwawcha-dev] + (https://github.com/xarvynx)


---

## 🙏 Acknowledgments

- [HaveIBeenPwned](https://haveibeenpwned.com/) for the breach API
- [OWASP](https://owasp.org/) for password security guidelines
- [NIST SP 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html) for password standards
- The open-source community for inspiration and tools

---

<div align="center">

**⭐ If you found this project helpful, please give it a star! ⭐**

Made with ❤️ and ☕

</div>
