# Append shellcode to the end of an image and return its offset
# It works with all file, not just images, but that's why I needed it
#
# author: spawntty

import sys

with open(sys.argv[1], "rb") as img_file:
    img = img_file.read()
    
img_pad_len = (16 - (len(img) % 16)) % 16
img_padded = img + (b"\x00" * img_pad_len)

offset = len(img_padded)

with open(sys.argv[2], "rb") as sh_file:
    sh = sh_file.read()
    
final_data = img_padded + sh

with open("output.png", "wb") as out:
    out.write(final_data)
    
print(f"[+] Image size: {len(img)} bytes")
print(f"[+] Padding added: {img_pad_len} bytes")
print(f"[+] Shellcode size: {len(sh)} bytes")
print(f"[+] Shellcode offset: {hex(offset)}")
print(f"[+] Final size: {len(final_data)} bytes")
