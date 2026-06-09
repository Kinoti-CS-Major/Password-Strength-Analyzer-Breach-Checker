#!/usr/bin/env python3
import sys
import math
import hashlib
import argparse
import getpass
import requests
from colorama import init, Fore, Style

# Initialize colorama for standard Windows/Linux/macOS terminal coloring
init(autoreset=True)

# Common Keyboard walk definitions
KEYBOARD_WALKS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"]

# Leet speak translations dictionary
LEET_DICT = {
    '3': 'e', '4': 'a', '@': 'a', '1': 'i', '!': 'i', '0': 'o',
    '5': 's', '$': 's', '7': 't', '8': 'b', '9': 'g'
}

# Embedded high-risk fallback dictionary if common-passwords.txt is missing
FALLBACK_DICT = {
    "password", "123456", "123456789", "qwerty", "admin", "welcome", 
    "letmein", "secret", "password123", "oracle", "charlie"
}

def load_dictionary(filepath="common-passwords.txt"):
    """Loads a flat-file dictionary into memory. Falls back to default on error."""
    words = set()
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                val = line.strip().lower()
                if val:
                    words.add(val)
        return words
    except FileNotFoundError:
        return FALLBACK_DICT

def calculate_entropy(password):
    """Calculates password information entropy based on character sets used."""
    if not password:
        return 0, 0
    
    pool_size = 0
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    # Special characters are categorized as non-alphanumeric printable characters
    has_special = any(not c.isalnum() for c in password)

    if has_lower: pool_size += 26
    if has_upper: pool_size += 26
    if has_digit: pool_size += 10
    if has_special: pool_size += 33

    entropy = len(password) * math.log2(pool_size) if pool_size > 0 else 0
    return entropy, pool_size

def translate_leet(password):
    """Translates common leet speak characters to check alignment with root words."""
    translated = []
    for char in password.lower():
        translated.append(LEET_DICT.get(char, char))
    return "".join(translated)

def detect_patterns(password, dictionary_set):
    """Checks for repeating letters, keyboard paths, dictionary words, and leet variations."""
    pw_lower = password.lower()
    pw_de_leet = translate_leet(password)
    
    # 1. Check direct repetitions (e.g. 'aaa')
    for i in range(len(pw_lower) - 2):
        if pw_lower[i] == pw_lower[i+1] == pw_lower[i+2]:
            return "Consecutive repeated characters"

    # 2. Check Keyboard walks of length 4 or more
    for walk in KEYBOARD_WALKS:
        for i in range(len(walk) - 3):
            forward_seq = walk[i:i+4]
            reverse_seq = forward_seq[::-1]
            if forward_seq in pw_lower or reverse_seq in pw_lower:
                return f"Keyboard walk sequence ('{forward_seq}')"

    # 3. Check Dictionary / Leet matches
    if pw_lower in dictionary_set or pw_de_leet in dictionary_set:
        return "Common dictionary word matching"

    # 4. Check length boundaries
    if len(password) < 8:
        return "Length below safe minimum"

    return None

def check_pwned_k_anonymity(password):
    """Queries HaveIBeenPwned anonymously via local SHA-1 range checks."""
    try:
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]
        
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        response = requests.get(url, timeout=5)
        
        if response.status_code == 200:
            for line in response.text.splitlines():
                line_suffix, count = line.split(':')
                if line_suffix == suffix:
                    return int(count)
        return 0
    except Exception:
        return -1 # Connection/API Error code

def generate_report(password, dictionary_set):
    """Gathers calculations and builds the formatted terminal reports."""
    entropy, _ = calculate_entropy(password)
    pwned_hits = check_pwned_k_anonymity(password)
    pattern_flag = detect_patterns(password, dictionary_set)

    # Determine Verdict Class
    if pwned_hits > 0:
        verdict = f"{Fore.RED}COMPROMISED ✖"
    elif entropy < 40 or pattern_flag:
        verdict = f"{Fore.YELLOW}WEAK ⚠"
    elif entropy < 65:
        verdict = f"{Fore.CYAN}MEDIUM"
    else:
        verdict = f"{Fore.GREEN}STRONG ✓"

    pwned_str = f"{pwned_hits:,}" if pwned_hits >= 0 else "Connection Error"
    pattern_str = f"{Fore.RED}{pattern_flag}" if pattern_flag else "None"

    # Print Formatted Unicode Box
    print(f"{Fore.CYAN}╔══════════════════════════════════════════════╗")
    print(f"{Fore.CYAN}║  {Style.BRIGHT}PASSWORD SECURITY EVALUATION REPORT{Style.NORMAL}        ║")
    print(f"{Fore.CYAN}╠══════════════════════════════════════════════╣")
    print(f"{Fore.CYAN}║  {Fore.WHITE}Entropy:{Style.RESET_ALL}        {entropy:5.1f} bits                     ║")
    print(f"{Fore.CYAN}║  {Fore.WHITE}Breaches:{Style.RESET_ALL}       {pwned_str:10}                     ║")
    print(f"{Fore.CYAN}║  {Fore.WHITE}Pattern Flags:{Style.RESET_ALL}  {pattern_str:25}    ║")
    print(f"{Fore.CYAN}║  {Fore.WHITE}Final Verdict:{Style.RESET_ALL}  {verdict:20}               ║")
    print(f"{Fore.CYAN}╚══════════════════════════════════════════════╝")

def process_batch(filepath, dictionary_set):
    """Processes bulk target list from a text file, reporting metrics cleanly."""
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            lines = [line.strip() for line in f if line.strip()]
        
        if not lines:
            print(f"{Fore.RED}Error: Batch audit file is empty.")
            return

        print(f"\n{Fore.CYAN}STARTING BATCH AUDIT SEQUENCE: {len(lines)} targets loaded...")
        print(f"{Fore.WHITE}{'Index':<6} | {'Entropy':<10} | {'Breaches':<12} | {'Pattern Risk':<25} | {'Verdict':<15}")
        print("-" * 80)

        for idx, pw in enumerate(lines, 1):
            entropy, _ = calculate_entropy(pw)
            hits = check_pwned_k_anonymity(pw)
            pattern = detect_patterns(pw, dictionary_set)
            
            p_str = pattern if pattern else "None"
            h_str = f"{hits:,}" if hits >= 0 else "Err"
            
            # Simple verdict mapping
            if hits > 0:
                verdict = f"{Fore.RED}COMPROMISED"
            elif entropy < 40 or pattern:
                verdict = f"{Fore.YELLOW}WEAK"
            else:
                verdict = f"{Fore.GREEN}STRONG"

            print(f"#{idx:<4} | {entropy:8.1f} | {h_str:<12} | {p_str[:23]:<25} | {verdict}")

    except Exception as e:
        print(f"{Fore.RED}Failed to complete batch audit: {str(e)}")

def main():
    parser = argparse.ArgumentParser(description="SENTINEL // CLI Password Analysis & Triage Tool")
    parser.add_argument("--batch", help="Path to text file containing target strings (one per line).", default=None)
    parser.add_argument("--dict", help="Custom dictionary file path.", default="common-passwords.txt")
    args = parser.parse_args()

    # Ingest dictionary mappings
    dictionary_set = load_dictionary(args.dict)

    if args.batch:
        # Batch audit mode execution
        process_batch(args.batch, dictionary_set)
    else:
        # Standard secure input prompt mode
        print(f"{Fore.CYAN}SENTINEL PW_CHECKER // Secure Interactive Mode")
        try:
            password = getpass.getpass("Enter password to evaluate (input will not echo): ")
            if not password:
                print(f"{Fore.RED}Error: Input empty. Terminating.")
                sys.exit(1)
            generate_report(password, dictionary_set)
        except (KeyboardInterrupt, SystemExit):
            print(f"\n{Fore.YELLOW}Audit sequence aborted by user.")

if __name__ == "__main__":
    main()