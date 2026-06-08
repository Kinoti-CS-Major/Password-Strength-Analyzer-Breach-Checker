# Password Strength Analyzer & Breach Checker

A self-contained, client-side web tool designed to evaluate password strength and check exposure against historical data breaches. This application is constructed entirely in a single file with native HTML, CSS, and vanilla JavaScript—requiring no external build tools, frameworks, or database servers.

## Key Features

* **Real-Time Entropy Calculation:** Computes password strength using Shannon entropy principles based on length and character set diversity (uppercase, lowercase, numerical digits, and special symbols).
* **Pattern & Sequential Walk Alerts:** Scans the input string locally to flag common password pitfalls, including:
  * Sequential keyboard paths (e.g., `qwerty`, `asdf`) and numerical series.
  * Repeated characters (e.g., `aaa`).
  * Basic dictionary words (e.g., `password`, `admin`).
  * Easily guessable date/year formats.
* **Privacy-Preserving Breach Check:** Connects to the HaveIBeenPwned API using the **k-Anonymity model** [3]. 
  * The password is locally hashed using SHA-1 via the browser's native Web Crypto API.
  * Only the first 5 characters of the hash are transmitted over the network.
  * The matching and verification of the remaining hash suffix occur completely on the client side, ensuring the plaintext password never leaves your browser.
* **Cryptographic Generator:** Includes a built-in generator that utilizes cryptographically secure pseudorandom numbers (`crypto.getRandomValues`) to output custom-length keys.

## Technical Details

- **Language:** HTML5, CSS3, ES6 JavaScript
- **API Integration:** HaveIBeenPwned Range API (`api.pwnedpasswords.com/range/`)
- **Zero Dependencies:** No external JavaScript frameworks or packages are required. Cryptographic hashing is handled natively by the browser's `SubtleCrypto` interface.

## How It Works (k-Anonymity Visualized)

1. **Local Hashing:** `Password123!` ➔ `SHA-1` ➔ `F0E4E42B6A349272FF0D642C9C22C0A5F2D99818`
2. **Network Query:** The client sends only the first 5 characters (`F0E4E`) to the HIBP API [3].
3. **API Response:** The API returns a list of all breached hash suffixes starting with `F0E4E` along with their respective breach counts [3].
4. **Local Match:** The script compares the remaining suffix (`42B6A349272FF0D642C9C22C0A5F2D99818`) against the returned list to display the result [3].

## Getting Started

1. Clone or download this repository.
2. Open the `.html` file in any modern web browser.
3. *Note:* Because the Web Crypto API (`crypto.subtle`) is restricted to secure contexts in most browsers, the breach checking functionality requires the file to be served over `HTTPS` or accessed locally via `localhost` or a local file pathway (`file://`).
