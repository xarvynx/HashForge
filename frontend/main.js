const CONFIG = {
    API_BASE_URL: 'http://127.0.0.1:5000/api',
    DEBOUNCE_DELAY_MS: 350
};

class SecurityAPIClient {
    static async request(endpoint, options = {}) {
        const url = `${CONFIG.API_BASE_URL}${endpoint}`;
        const headers = {
            'Content-Type': 'application/json',
            ...options.headers
        };

        try {
            const response = await fetch(url, { ...options, headers });
            
            if (!response.ok) {
                const errorData = await response.json().catch(() => ({}));
                throw new Error(errorData.detail?.[0]?.msg || `HTTP Error ${response.status}`);
            }

            return await response.json();
        } catch (error) {
            console.error(`[API Error] ${endpoint}:`, error.message);
            throw error;
        }
    }

    static async analyzePassword(password, checkBreach = true) {
        return this.request('/analyze', {
            method: 'POST',
            body: JSON.stringify({
                password: password,
                check_breach: checkBreach
            })
        });
    }

    static async generatePassword(length = 16, options = {}) {
        const payload = {
            length: length,
            use_uppercase: options.useUppercase ?? true,
            use_digits: options.useDigits ?? true,
            use_symbols: options.useSymbols ?? true
        };
        return this.request('/generate', {
            method: 'POST',
            body: JSON.stringify(payload)
        });
    }

    static async generatePassphrase(wordCount = 4, separator = '-', capitalize = true) {
        return this.request('/generate/passphrase', {
            method: 'POST',
            body: JSON.stringify({
                word_count: wordCount,
                separator: separator,
                capitalize: capitalize
            })
        });
    }

    static async generatePin(length = 6) {
        return this.request(`/generate/pin?length=${encodeURIComponent(length)}`, {
            method: 'POST'
        });
    }

    static async checkBreach(password) {
        return this.request('/breach-check', {
            method: 'POST',
            body: JSON.stringify({ password })
        });
    }
}

document.addEventListener('DOMContentLoaded', () => {
    // DOM Cache - match existing HTML IDs
    const passwordInput = document.getElementById('password');
    const togglePasswordBtn = document.getElementById('toggle-password');
    const strengthMeter = document.getElementById('password-strength');
    const strengthLabel = document.querySelector('.result .status');
    const analyseBtn = document.querySelector('.analyse');

    let debounceTimer = null;

    if (togglePasswordBtn && passwordInput) {
        togglePasswordBtn.addEventListener('click', () => {
            const isPassword = passwordInput.type === 'password';
            passwordInput.type = isPassword ? 'text' : 'password';
            togglePasswordBtn.setAttribute('aria-label', isPassword ? 'Hide Password' : 'Show Password');
        });
    }

    if (passwordInput) {
        passwordInput.addEventListener('input', (e) => {
            const password = e.target.value;

            clearTimeout(debounceTimer);

            if (!password) {
                resetUI();
                return;
            }

            debounceTimer = setTimeout(() => {
                executeAnalysis(password);
            }, CONFIG.DEBOUNCE_DELAY_MS);
        });
    }

    async function executeAnalysis(password) {
        try {
            const result = await SecurityAPIClient.analyzePassword(password, true);
            renderAnalysisResult(result);
        } catch (error) {
            renderError(error.message);
        }
    }

    function renderAnalysisResult(data) {
        const { score, strength, entropy, crack_time, feedback, breached } = data;

        if (strengthMeter) strengthMeter.value = score;
        if (strengthLabel) {
            strengthLabel.textContent = `${strength} (${score}/100)`;
            strengthLabel.className = `status strength-${strength.toLowerCase().replace(/\s+/g, '-')}`;
        }

        // Update description cards with entropy and crack time
        const cards = document.querySelectorAll('.description .card');
        if (cards.length >= 2) {
            cards[0].querySelector('p').textContent = `${entropy.toFixed(1)} bits entropy`;
            cards[1].querySelector('p').textContent = `GPU crack: ${crack_time?.gpu_cluster || 'Unknown'}`;
        }

        // Update breach status in second card
        if (breached && cards.length >= 2) {
            cards[1].querySelector('p').textContent = '⚠️ Found in data breach!';
        }
    }

    // Generate password - update input and re-analyze
    if (analyseBtn) {
        analyseBtn.addEventListener('click', async () => {
            if (!passwordInput || !passwordInput.value) return;
            
            try {
                const result = await SecurityAPIClient.generatePassword(16);
                if (passwordInput) {
                    passwordInput.value = result.password;
                    executeAnalysis(result.password);
                }
            } catch (error) {
                console.error('Generation Failed:', error.message);
            }
        });
    }

    function resetUI() {
        if (strengthMeter) strengthMeter.value = 0;
        if (strengthLabel) {
            strengthLabel.textContent = 'None';
            strengthLabel.className = 'status';
        }
        const cards = document.querySelectorAll('.description .card');
        if (cards.length >= 2) {
            cards[0].querySelector('p').textContent = '';
            cards[1].querySelector('p').textContent = 'Security checks';
        }
    }

    function renderError(message) {
        if (strengthLabel) {
            strengthLabel.textContent = `Error: ${message}`;
            strengthLabel.className = 'status strength-error';
        }
    }
});