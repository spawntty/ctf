#!/usr/bin/env python3
import argparse
import sys
from os import urandom
import hashlib
from Crypto.Cipher import AES

# 16 random bytes key
KEY = urandom(16)

def pad(b: bytes) -> bytes:
    """PKCS#7 pad bytes to AES.block_size"""
    pad_len = AES.block_size - (len(b) % AES.block_size)
    return b + bytes([pad_len]) * pad_len

def aesenc(plaintext: bytes, key: bytes) -> bytes:
    # derive a 32-byte key from provided key (sha256)
    k = hashlib.sha256(key).digest()
    iv = b'\x00' * AES.block_size
    plaintext = pad(plaintext)
    cipher = AES.new(k, AES.MODE_CBC, iv)
    return cipher.encrypt(plaintext)

def print_byte_array(name: str, data: bytes) -> None:
    """Print a C-style BYTE name[] = { 0x.., ... }; with 16 bytes per line."""
    print(f'BYTE {name}[] = {{')
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_values = ', '.join('0x{:02x}'.format(b) for b in chunk)
        if i + 16 < len(data):
            print('    ' + hex_values + ',')
        else:
            print('    ' + hex_values)
    print('};\n')

def main():
    parser = argparse.ArgumentParser(description="Encrypt with AES-CBC (using random key) strings or binary files")
   
    parser.add_argument('-t', '--type',
                        choices=['string', 'file'],
                        default='string',
                        help='Encrypt a string or a binary file (default: \"string\")')
        
    parser.add_argument('-s', '--string',
                        help='Input string (required when type is \"string\")')
    
    parser.add_argument('-i', '--input',
                        help='Input file path (required when type is \"file\")')
    
    parser.add_argument('-o', '--output',
                        help='Output file path (if not specified when type is \"file\" the encrypted data will only be printed; when written, file contains ciphertext)')
    
    args = parser.parse_args()
    
    if args.type == 'string':
        if not args.string:
            parser.error('--string is required when type is \"string\"')
        
        print(f"[+] Input string: {args.string}")

        # append null byte before encryption
        plaintext = args.string.encode() + b"\x00"
        ciphertext = aesenc(plaintext, KEY)

        print("[+] AES Key:")
        print_byte_array('AESkey', KEY)

        print("[+] AES-CBC encrypted data (payload):")
        print_byte_array('payload', ciphertext)

    elif args.type == 'file':
        if not args.input:
            parser.error('--input is required when type is \"file\"')
        
        print(f"[+] Reading {args.input}...")
        try:
            plaintext = open(args.input, "rb").read()
        except Exception as e:
            print("Failed to open/read file:", e)
            sys.exit(1)

        ciphertext = aesenc(plaintext, KEY)

        if args.output:
            print(f"[+] Writing ciphertext into {args.output}")
            try:
                with open(args.output, "wb") as out_f:
                    out_f.write(ciphertext)
            except Exception as e:
                print("Failed to write output file:", e)
                sys.exit(1)
        else:
            print("[+] No output specified, printing only...")

        print("[+] AES Key:")
        print_byte_array('AESkey', KEY)
        
        print("[+] AES-CBC encrypted data (payload):")
        print_byte_array('payload', ciphertext)

if __name__ == "__main__":
    main()
