import argparse
import sys

def xor(data, key):
    if not key:
        raise ValueError("Key must not be empty")

    if isinstance(data, str):
        data = data.encode()
    if isinstance(key, str):
        key = key.encode()
    
    result = bytearray()
    key_len = len(key)
    for i, byte in enumerate(data):
        result.append(byte ^ key[i % key_len])
    
    return bytes(result)

def printCiphertext(ciphertext: bytes) -> None:
    print('BYTE data[] = {')
    for i in range(0, len(ciphertext), 16):
        chunk = ciphertext[i:i+16]
        hex_values = ', '.join('0x{:02x}'.format(b) for b in chunk)
        if i + 16 < len(ciphertext):
            print('    ' + hex_values + ',')
        else:
            print('    ' + hex_values)
    print('};')

def main():
    parser = argparse.ArgumentParser(description="Encrypt with XOR strings or shellcode binary")
   
    parser.add_argument('-t', '--type',
                        choices=['string', 'file'],
                        default='string',
                        help='Encrypt a string or a binary file (default: "string")')
    
    parser.add_argument('-k', '--key',
                        help='XOR encryption key (required)')
    
    parser.add_argument('-s', '--string',
                        help='Input string (required when type is "string")')
    
    parser.add_argument('-i', '--input',
                        help='Input file path (required when type is "file")')
    
    parser.add_argument('-o', '--output',
                        help='Output file path (if not specified when the type is "file" the encrypted data will be only printed)')
    
    args = parser.parse_args()
    
    if args.type == 'string':
        if not args.key or not args.string:
            parser.error('--key and --string are required when type is "string"')
        
        print(f"[+] XOR Key: {args.key}")
        print(f"[+] Input string: {args.string}")

        # append null byte (0x00) before encryption
        plaintext = args.string.encode() + b"\x00"

        cipher = xor(plaintext, args.key)
        
        print("[+] XOR encrypted data (C array):")
        printCiphertext(cipher)
        

    elif args.type == 'file':
        if not args.key or not args.input:
            parser.error('--key and --input are required when type is "file"')
        
        print(f"[+] XOR Key: {args.key}")
        
        print(f"[+] Reading {args.input}...")
        try:
            plaintext = open(args.input, "rb").read()
        except Exception as e:
            print("Failed to open/read file:", e)
            sys.exit(1)

        cipher = xor(plaintext, args.key)

        if args.output:
            print(f"[+] Writing XOR encrypted data into {args.output}")
            try:
                with open(args.output, "wb") as xored_file:
                    xored_file.write(cipher)
            except Exception as e:
                print("Failed to write output file:", e)
                sys.exit(1)
        else:
            print("[+] No output specified, printing only...")
            
        print("[+] XOR encrypted data (C array):")
        printCiphertext(cipher)
        

if __name__ == "__main__":
    main()
