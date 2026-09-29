/**
 * Security Suite - Frontend API Integration Module
 * Handles API communication with FastAPI backend endpoints.
 */

const CONFIG = {
    API_BASE_URL: 'http://127.0.0.1:8000/api',
    DEBOUNCE_DELAY_MS: 350
};

class SecurityAPIClient {
    /**
     * Generic asynchronous HTTP fetch wrapper.
     */
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

    /**
     * POST /api/analyze
     */
    static async analyzePassword(password, checkBreach = true) {
        return this.request('/analyze', {
            method: 'POST',
            body: JSON.stringify({
                password: password,
                check_breach: checkBreach
            })
        });
    }

    /**
     * POST /api/generate
     */
    static async generatePassword(length = 16, options = {}) {
        const payload = {
            length: length,
            use_uppercase: options.useUppercase ?? true,
            use_lowercase: options.useLowercase ?? true,
            use_digits: options.useDigits ?? true,
            use_symbols: options.useSymbols ?? true
        };
        return this.request('/generate', {
            method: 'POST',
            body: JSON.stringify(payload)
        });
    }

    /**
     * POST /api/generate/passphrase
     */
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

    /**
     * POST /api/generate/pin?length=X
     */
    static async generatePin(length = 6) {
        return this.request(`/generate/pin?length=${encodeURIComponent(length)}`, {
            method: 'POST'
        });
    }

    /**
     * POST /api/breach-check
     */
    static async checkBreach(password) {
        return this.request('/breach-check', {
            method: 'POST',
            body: JSON.stringify({ password })
        });
    }
}

// ============================================================================
// DOM Controller & Application Lifecycle
// ============================================================================

document.addEventListener('DOMContentLoaded', () => {
    // DOM Cache
    const passwordInput = document.getElementById('password-input');
    const togglePasswordBtn = document.getElementById('toggle-password-btn');
    const strengthMeter = document.getElementById('strength-meter');
    const strengthLabel = document.getElementById('strength-label');
    const entropyValue = document.getElementById('entropy-value');
    const crackTimeValue = document.getElementById('crack-time-value');
    const breachStatus = document.getElementById('breach-status');
    const feedbackList = document.getElementById('feedback-list');

    // Generator Controls
    const generateBtn = document.getElementById('generate-btn');
    const lengthSlider = document.getElementById('length-slider');
    const lengthDisplay = document.getElementById('length-display');

    let debounceTimer = null;

    // 1. Password Visibility Toggle
    if (togglePasswordBtn && passwordInput) {
        togglePasswordBtn.addEventListener('click', () => {
            const isPassword = passwordInput.type === 'password';
            passwordInput.type = isPassword ? 'text' : 'password';
            togglePasswordBtn.setAttribute('aria-label', isPassword ? 'Hide Password' : 'Show Password');
        });
    }

    // 2. Real-time Analysis Driver (Debounced)
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

    // 3. Analyze Password Core Execution
    async function executeAnalysis(password) {
        try {
            const result = await SecurityAPIClient.analyzePassword(password, true);
            renderAnalysisResult(result);
        } catch (error) {
            renderError(error.message);
        }
    }

    // 4. Render FastAPI `AnalyzeResponse` Model
    function renderAnalysisResult(data) {
        const { score, strength, entropy, crack_time, feedback, breached } = data;

        // Progress bar and score
        if (strengthMeter) strengthMeter.value = score;
        if (strengthLabel) {
            strengthLabel.textContent = `${strength} (${score}/100)`;
            strengthLabel.className = `strength-text strength-${strength.toLowerCase().replace(/\s+/g, '-')}`;
        }

        // Metrics
        if (entropyValue) entropyValue.textContent = `${entropy.toFixed(1)} bits`;
        if (crackTimeValue) crackTimeValue.textContent = crack_time;

        // Breach Status
        if (breachStatus) {
            if (breached) {
                breachStatus.textContent = '⚠️ Found in known data breach!';
                breachStatus.className = 'status-alert status-breached';
            } else {
                breachStatus.textContent = '✓ No known breach recorded';
                breachStatus.className = 'status-alert status-safe';
            }
        }

        // Feedback & Suggestions
        if (feedbackList) {
            feedbackList.innerHTML = '';
            
            if (feedback.warning) {
                const warningLi = document.createElement('li');
                warningLi.className = 'feedback-warning';
                warningLi.textContent = feedback.warning;
                feedbackList.appendChild(warningLi);
            }

            if (feedback.suggestions && feedback.suggestions.length > 0) {
                feedback.suggestions.forEach(suggestion => {
                    const li = document.createElement('li');
                    li.textContent = suggestion;
                    feedbackList.appendChild(li);
                });
            }
        }
    }

    // 5. Password Generation Handler
    if (generateBtn) {
        generateBtn.addEventListener('click', async () => {
            const length = lengthSlider ? parseInt(lengthSlider.value, 10) : 16;
            
            try {
                const result = await SecurityAPIClient.generatePassword(length);
                if (passwordInput) {
                    passwordInput.value = result.password;
                    // Trigger live analysis manually on generated result
                    executeAnalysis(result.password);
                }
            } catch (error) {
                console.error('Generation Failed:', error.message);
            }
        });
    }

    // 6. UI Synchronization Helpers
    if (lengthSlider && lengthDisplay) {
        lengthSlider.addEventListener('input', (e) => {
            lengthDisplay.textContent = e.target.value;
        });
    }

    function resetUI() {
        if (strengthMeter) strengthMeter.value = 0;
        if (strengthLabel) strengthLabel.textContent = 'None';
        if (entropyValue) entropyValue.textContent = '0 bits';
        if (crackTimeValue) crackTimeValue.textContent = 'Instant';
        if (breachStatus) breachStatus.textContent = 'Not Checked';
        if (feedbackList) feedbackList.innerHTML = '';
    }

    function renderError(message) {
        if (strengthLabel) {
            strengthLabel.textContent = `Error: ${message}`;
            strengthLabel.className = 'strength-text strength-error';
        }
    }
});