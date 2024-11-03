# Hash Cracker and Generator Tool

This tool is designed to generate and crack password hashes using Python. It supports `md5` and `sha256` hashing algorithms and provides colored output for better readability, thanks to the `colorama` library.

## Installation

1. Clone this repository to your local machine:
   ```bash
   git clone https://github.com/yourusername/HashCrackerTool.git
   ```
2. Install the required library:
   ```bash
   pip install colorama
   ```
3. Run the script:
   ```bash
   python Hash_Cracker_and_Generator_Tool.py
   ```

## Usage

### Generate a Hash
Generate a hash from a password using the specified algorithm:
```bash
python Hash_Cracker_Tool.py -a [algorithm] -p [password]
```
**Example**:
```bash
python Hash_Cracker_Tool.py -a md5 -p mysecretpassword
```

### Crack a Hash
Attempt to crack a hash using a wordlist:
```bash
python Hash_Cracker_Tool.py -a [algorithm] -H [hash] -w [wordlist_path]
```
**Example**:
```bash
python Hash_Cracker_Tool.py -a sha256 -H e3afed0047b08059d0fada10f400c1e5 -w /path/to/wordlist.txt
```

## Contributing

To contribute:
1. Fork the repo
2. Create a new branch for your feature
3. Submit a pull request when done

All contributions are welcome!

## License





