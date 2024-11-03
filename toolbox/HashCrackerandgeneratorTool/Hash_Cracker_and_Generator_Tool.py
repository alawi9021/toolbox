import argparse
import hashlib
from colorama import Fore, Style, init


init(autoreset=True)

def hash_password(password, algorithm):
    """Hash a password using the specified algorithm."""
    try:
        if algorithm == 'md5':
            return hashlib.md5(password.encode()).hexdigest()
        elif algorithm == 'sha256':
            return hashlib.sha256(password.encode()).hexdigest()
        else:
            raise ValueError("Unsupported hashing algorithm. Use 'md5' or 'sha256'.")
    except Exception as e:
        print(Fore.RED + f"Error hashing password: {e}")
        return None

def crack_hash(hash_to_crack, wordlist_path, algorithm):
    """Attempt to crack the hash using a given wordlist and hashing algorithm."""
    try:
        with open(wordlist_path, 'r', encoding='latin-1') as file:
            for word in file:
                word = word.strip()  
                hashed_word = hash_password(word, algorithm)
                print(Fore.YELLOW + f"Trying: {word} -> {hashed_word}")
                if hashed_word == hash_to_crack:
                    print(Fore.GREEN + f"[+] Password found: {word}")
                    return
        print(Fore.RED + "[-] Password not found in the wordlist.")
    except FileNotFoundError:
        print(Fore.RED + "Error: Wordlist file not found.")
    except Exception as e:
        print(Fore.RED + f"An error occurred: {e}")

def main():
    parser = argparse.ArgumentParser(description="A simple hash cracker and generator tool using hashlib.")
    parser.add_argument("-a", "--algorithm", required=True, choices=['md5', 'sha256'], help="The hashing algorithm (md5 or sha256).")
    parser.add_argument("-H", "--hash", help="The hash to crack.")
    parser.add_argument("-p", "--password", help="Generate a hash from this password.")
    parser.add_argument("-w", "--wordlist", help="Path to the wordlist file for cracking.")

    args = parser.parse_args()

    
    if args.password:
        generated_hash = hash_password(args.password, args.algorithm)
        if generated_hash:
            print(Fore.CYAN + f"The {args.algorithm.upper()} hash for '{args.password}' is: {generated_hash}")
        return

    
    if args.hash and args.wordlist:
        print(Fore.BLUE + f"Attempting to crack the hash: {args.hash} using wordlist: {args.wordlist}")
        crack_hash(args.hash, args.wordlist, args.algorithm)
    else:
        print(Fore.RED + "[-] Insufficient arguments provided. Use -p to generate a hash or -H and -w to crack a hash.")

if __name__ == "__main__":
    main()

