# AES File Encryptor

## Overview
AES File Encryptor is a secure file encryption tool that uses the Advanced Encryption Standard (AES) algorithm to encrypt and decrypt files, ensuring data confidentiality and integrity. This project is licensed under the GNU General Public License v3.0 (GPLv3).

## Features
- AES-256 encryption and decryption
- Secure password-based encryption (PBE)
- Cross-platform compatibility
- Simple and efficient command-line interface

## Installation
1. Clone this repository:
   ```sh
   git clone https://github.com/Sachaniyahet/aes-file-encryptor.git
   cd aes-file-encryptor
   ```
2. Install dependencies (if required):
   ```sh
   pip install -r requirements.txt
   ```

## Usage
### Encrypt a file:
```sh
python3 encryptor.py -e -i input.txt -o encrypted.aes
```

### Decrypt a file:
```sh
python3 encryptor.py -d -i encrypted.aes -o decrypted.txt
```

## License
This project is licensed under the GNU General Public License v3.0. See the [LICENSE](LICENSE) file for details.

## Contribution
Contributions are welcome! Feel free to submit issues and pull requests.

## Author
[Sachaniya Het](https://github.com/Sachaniyahet)
