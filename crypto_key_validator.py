"""
Cryptocurrency Private Key Validator and Import Utility
Supports multiple key formats: Hexadecimal, WIF, Seed Phrases, and various lengths
"""

import re
import hashlib
import binascii
from typing import Dict, List, Tuple, Optional
from enum import Enum


class KeyType(Enum):
    """Enumeration of supported key types"""
    HEXADECIMAL = "Hexadecimal Private Key"
    WIF_COMPRESSED = "WIF Compressed"
    WIF_UNCOMPRESSED = "WIF Uncompressed"
    SEED_PHRASE_12 = "12-Word Seed Phrase"
    SEED_PHRASE_24 = "24-Word Seed Phrase"
    SEED_PHRASE_18 = "18-Word Seed Phrase"
    SEED_PHRASE_15 = "15-Word Seed Phrase"
    ETHEREUM_KEY = "Ethereum Private Key"
    UNKNOWN = "Unknown Format"


class CryptoKeyValidator:
    """
    Main validator class for cryptocurrency private keys
    """
    
    # Base58 alphabet for WIF encoding
    BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    
    # BIP39 word list (first 50 words as example - full list should be loaded)
    # In production, load from a complete BIP39 wordlist file
    BIP39_SAMPLE_WORDS = {
        'abandon', 'ability', 'able', 'about', 'above', 'absent', 'absorb', 'abstract',
        'absurd', 'abuse', 'access', 'accident', 'account', 'accuse', 'achieve', 'acid',
        'acoustic', 'acquire', 'across', 'act', 'action', 'actor', 'actress', 'actual',
        'adapt', 'add', 'addict', 'address', 'adjust', 'admit', 'adult', 'advance',
        'advice', 'aerobic', 'affair', 'afford', 'afraid', 'again', 'age', 'agent',
        'agree', 'ahead', 'aim', 'air', 'airport', 'aisle', 'alarm', 'album'
    }
    
    def __init__(self):
        """Initialize the validator"""
        self.validation_results = []
    
    @staticmethod
    def base58_decode(s: str) -> Optional[bytes]:
        """Decode Base58 string to bytes"""
        try:
            decoded = 0
            multi = 1
            for char in reversed(s):
                if char not in CryptoKeyValidator.BASE58_ALPHABET:
                    return None
                decoded += multi * CryptoKeyValidator.BASE58_ALPHABET.index(char)
                multi *= 58
            
            # Convert to bytes
            hex_str = hex(decoded)[2:]
            if len(hex_str) % 2:
                hex_str = '0' + hex_str
            
            # Add leading zeros
            leading_zeros = len(s) - len(s.lstrip('1'))
            return b'\x00' * leading_zeros + bytes.fromhex(hex_str)
        except Exception:
            return None
    
    @staticmethod
    def validate_checksum(data: bytes) -> bool:
        """Validate checksum for WIF keys"""
        try:
            payload = data[:-4]
            checksum = data[-4:]
            hash_result = hashlib.sha256(hashlib.sha256(payload).digest()).digest()
            return hash_result[:4] == checksum
        except Exception:
            return False
    
    def is_valid_hexadecimal(self, key: str) -> Tuple[bool, Dict]:
        """
        Check if the key is a valid hexadecimal private key
        Supports various lengths (32, 64, 128 characters, etc.)
        """
        key = key.strip().lower()
        
        # Remove common prefixes
        if key.startswith('0x'):
            key = key[2:]
        
        # Check if it's hexadecimal
        if not re.match(r'^[0-9a-f]+$', key):
            return False, {}
        
        # Determine key length and potential cryptocurrency
        key_length = len(key)
        potential_cryptos = []
        
        if key_length == 64:
            potential_cryptos = ['Bitcoin', 'Ethereum', 'Litecoin', 'Dogecoin', 'Most EVM chains']
        elif key_length == 32:
            potential_cryptos = ['Some alternate formats', 'Custom implementations']
        elif key_length in [128, 256]:
            potential_cryptos = ['Extended keys', 'Special implementations']
        elif 60 <= key_length <= 68:
            potential_cryptos = ['Possible valid key with minor variations']
        
        if potential_cryptos:
            return True, {
                'type': KeyType.HEXADECIMAL,
                'length': key_length,
                'normalized_key': key,
                'potential_cryptos': potential_cryptos,
                'confidence': 'High' if key_length == 64 else 'Medium'
            }
        
        return False, {}
    
    def is_valid_wif(self, key: str) -> Tuple[bool, Dict]:
        """
        Check if the key is a valid Wallet Import Format (WIF) key
        """
        key = key.strip()
        
        # WIF keys typically start with specific characters
        valid_prefixes = {
            '5': ('Bitcoin Mainnet Uncompressed', 'Bitcoin'),
            'K': ('Bitcoin Mainnet Compressed', 'Bitcoin'),
            'L': ('Bitcoin Mainnet Compressed', 'Bitcoin'),
            '9': ('Bitcoin Testnet Uncompressed', 'Bitcoin Testnet'),
            'c': ('Bitcoin Testnet Compressed', 'Bitcoin Testnet'),
            '6': ('Dogecoin', 'Dogecoin'),
            'Q': ('Dogecoin', 'Dogecoin'),
            'T': ('Litecoin', 'Litecoin'),
        }
        
        if not key or key[0] not in valid_prefixes:
            return False, {}
        
        # Decode and validate
        decoded = self.base58_decode(key)
        if decoded is None:
            return False, {}
        
        # Check length (should be 37 bytes for compressed, 38 for uncompressed)
        if len(decoded) not in [37, 38]:
            return False, {}
        
        # Validate checksum
        if not self.validate_checksum(decoded):
            return False, {}
        
        prefix_info = valid_prefixes.get(key[0], ('Unknown', 'Unknown'))
        is_compressed = len(decoded) == 38
        
        return True, {
            'type': KeyType.WIF_COMPRESSED if is_compressed else KeyType.WIF_UNCOMPRESSED,
            'format': prefix_info[0],
            'cryptocurrency': prefix_info[1],
            'compressed': is_compressed,
            'confidence': 'High'
        }
    
    def is_valid_seed_phrase(self, key: str) -> Tuple[bool, Dict]:
        """
        Check if the key is a valid BIP39 seed phrase
        """
        key = key.strip().lower()
        
        # Split into words
        words = re.split(r'\s+', key)
        word_count = len(words)
        
        # Valid seed phrase lengths
        valid_lengths = {12, 15, 18, 24}
        
        if word_count not in valid_lengths:
            return False, {}
        
        # Check if words are valid (simplified check)
        # In production, validate against complete BIP39 wordlist
        invalid_words = []
        for word in words:
            if not re.match(r'^[a-z]+$', word):
                invalid_words.append(word)
        
        if invalid_words and len(invalid_words) > word_count * 0.2:  # Allow 20% tolerance
            return False, {}
        
        key_type_map = {
            12: KeyType.SEED_PHRASE_12,
            15: KeyType.SEED_PHRASE_15,
            18: KeyType.SEED_PHRASE_18,
            24: KeyType.SEED_PHRASE_24
        }
        
        return True, {
            'type': key_type_map[word_count],
            'word_count': word_count,
            'potential_cryptos': ['Bitcoin', 'Ethereum', 'Most BIP39-compatible wallets'],
            'confidence': 'High' if not invalid_words else 'Medium',
            'note': 'BIP39 standard - widely compatible'
        }
    
    def is_ethereum_specific(self, key: str) -> Tuple[bool, Dict]:
        """
        Check for Ethereum-specific key format
        """
        key = key.strip()
        
        # Ethereum keys are 64 hex characters, often with 0x prefix
        if key.startswith('0x'):
            key_without_prefix = key[2:]
            if len(key_without_prefix) == 64 and re.match(r'^[0-9a-fA-F]+$', key_without_prefix):
                return True, {
                    'type': KeyType.ETHEREUM_KEY,
                    'normalized_key': key_without_prefix.lower(),
                    'potential_cryptos': ['Ethereum', 'BSC', 'Polygon', 'Arbitrum', 'Optimism', 'All EVM chains'],
                    'confidence': 'High'
                }
        
        return False, {}
    
    def validate_key(self, potential_key: str) -> Dict:
        """
        Main validation method - tries all validation methods
        """
        potential_key = potential_key.strip()
        
        if not potential_key:
            return {
                'valid': False,
                'error': 'Empty input'
            }
        
        # Try each validation method
        validators = [
            self.is_ethereum_specific,
            self.is_valid_wif,
            self.is_valid_seed_phrase,
            self.is_valid_hexadecimal,
        ]
        
        for validator in validators:
            is_valid, details = validator(potential_key)
            if is_valid:
                return {
                    'valid': True,
                    'input': potential_key[:20] + '...' if len(potential_key) > 20 else potential_key,
                    **details
                }
        
        # Check for partial matches or unusual formats
        analysis = self._analyze_unusual_format(potential_key)
        
        return {
            'valid': False,
            'input': potential_key[:20] + '...' if len(potential_key) > 20 else potential_key,
            'analysis': analysis
        }
    
    def _analyze_unusual_format(self, key: str) -> Dict:
        """
        Analyze keys that don't match standard formats
        """
        analysis = {
            'length': len(key),
            'contains_spaces': ' ' in key,
            'alphanumeric_only': key.replace(' ', '').isalnum(),
            'suggestions': []
        }
        
        # Check if it might be a hex key with typos
        hex_chars = sum(1 for c in key.lower() if c in '0123456789abcdef')
        if hex_chars / len(key) > 0.9:
            analysis['suggestions'].append('Might be hexadecimal with some invalid characters')
        
        # Check if it might be a seed phrase with issues
        words = key.lower().split()
        if 10 <= len(words) <= 25:
            analysis['suggestions'].append(f'Contains {len(words)} words - close to valid seed phrase length')
        
        return analysis


def print_banner():
    """Print application banner"""
    print("=" * 70)
    print("   CRYPTOCURRENCY PRIVATE KEY VALIDATOR & IMPORT UTILITY")
    print("=" * 70)
    print()


def print_validation_result(result: Dict):
    """Pretty print validation results"""
    print("\n" + "─" * 70)
    
    if result['valid']:
        print("✓ VALID KEY DETECTED")
        print(f"  Input: {result['input']}")
        print(f"  Type: {result['type'].value if isinstance(result['type'], KeyType) else result['type']}")
        
        if 'cryptocurrency' in result:
            print(f"  Cryptocurrency: {result['cryptocurrency']}")
        
        if 'potential_cryptos' in result:
            print(f"  Compatible with: {', '.join(result['potential_cryptos'])}")
        
        if 'confidence' in result:
            print(f"  Confidence Level: {result['confidence']}")
        
        if 'length' in result:
            print(f"  Key Length: {result['length']} characters")
        
        if 'word_count' in result:
            print(f"  Word Count: {result['word_count']}")
        
        if 'note' in result:
            print(f"  Note: {result['note']}")
        
        if 'compressed' in result:
            print(f"  Compression: {'Compressed' if result['compressed'] else 'Uncompressed'}")
    else:
        print("✗ INVALID OR UNRECOGNIZED KEY FORMAT")
        print(f"  Input: {result['input']}")
        
        if 'error' in result:
            print(f"  Error: {result['error']}")
        
        if 'analysis' in result:
            analysis = result['analysis']
            print(f"  Length: {analysis['length']} characters")
            
            if analysis['suggestions']:
                print("  Suggestions:")
                for suggestion in analysis['suggestions']:
                    print(f"    • {suggestion}")
    
    print("─" * 70)


def display_menu():
    """Display user menu"""
    print("\nOPTIONS:")
    print("  1. Validate a single key")
    print("  2. Validate multiple keys (batch mode)")
    print("  3. Read keys from file")
    print("  4. Display supported formats")
    print("  5. Exit")
    print()


def display_supported_formats():
    """Display information about supported formats"""
    print("\n" + "=" * 70)
    print("SUPPORTED KEY FORMATS")
    print("=" * 70)
    
    formats = [
        ("Hexadecimal Private Keys", "64 characters (0-9, a-f)", "Bitcoin, Ethereum, most cryptos"),
        ("WIF Keys", "51-52 characters, Base58", "Bitcoin, Litecoin, Dogecoin"),
        ("Seed Phrases (BIP39)", "12, 15, 18, or 24 words", "Most HD wallets"),
        ("Ethereum Keys", "64 hex chars with 0x prefix", "Ethereum and EVM chains"),
        ("Non-standard lengths", "32, 128, 256 characters", "Special implementations"),
    ]
    
    for name, format_desc, cryptos in formats:
        print(f"\n{name}:")
        print(f"  Format: {format_desc}")
        print(f"  Used by: {cryptos}")
    
    print("\n" + "=" * 70)


def validate_single_key(validator: CryptoKeyValidator):
    """Validate a single key from user input"""
    print("\nEnter the potential private key (or 'back' to return):")
    user_input = input("> ").strip()
    
    if user_input.lower() == 'back':
        return
    
    result = validator.validate_key(user_input)
    print_validation_result(result)


def validate_batch_keys(validator: CryptoKeyValidator):
    """Validate multiple keys"""
    print("\nEnter keys one per line. Enter 'done' when finished:")
    keys = []
    
    while True:
        line = input("> ").strip()
        if line.lower() == 'done':
            break
        if line:
            keys.append(line)
    
    if not keys:
        print("No keys entered.")
        return
    
    print(f"\nValidating {len(keys)} key(s)...")
    
    valid_count = 0
    for i, key in enumerate(keys, 1):
        print(f"\n[Key {i}/{len(keys)}]")
        result = validator.validate_key(key)
        print_validation_result(result)
        if result['valid']:
            valid_count += 1
    
    print(f"\n{'=' * 70}")
    print(f"SUMMARY: {valid_count}/{len(keys)} valid keys detected")
    print(f"{'=' * 70}")


def validate_from_file(validator: CryptoKeyValidator):
    """Read and validate keys from a file"""
    print("\nEnter the file path:")
    file_path = input("> ").strip()
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            keys = [line.strip() for line in f if line.strip()]
        
        if not keys:
            print("No keys found in file.")
            return
        
        print(f"\nFound {len(keys)} potential key(s) in file. Validating...")
        
        valid_count = 0
        for i, key in enumerate(keys, 1):
            print(f"\n[Key {i}/{len(keys)}]")
            result = validator.validate_key(key)
            print_validation_result(result)
            if result['valid']:
                valid_count += 1
        
        print(f"\n{'=' * 70}")
        print(f"SUMMARY: {valid_count}/{len(keys)} valid keys detected")
        print(f"{'=' * 70}")
        
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
    except Exception as e:
        print(f"Error reading file: {e}")


def main():
    """Main application loop"""
    print_banner()
    validator = CryptoKeyValidator()
    
    while True:
        display_menu()
        choice = input("Select an option (1-5): ").strip()
        
        if choice == '1':
            validate_single_key(validator)
        elif choice == '2':
            validate_batch_keys(validator)
        elif choice == '3':
            validate_from_file(validator)
        elif choice == '4':
            display_supported_formats()
        elif choice == '5':
            print("\nThank you for using Crypto Key Validator. Goodbye!")
            break
        else:
            print("\nInvalid option. Please select 1-5.")


if __name__ == "__main__":
    main()