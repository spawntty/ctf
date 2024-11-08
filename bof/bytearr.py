#!/usr/bin/env python3

import sys

def hex_to_dec(hex_string):
  byte_data = bytes.fromhex(hex_string.replace("\\x", ""))
  decimal_list = list(byte_data)
  return decimal_list

if len(sys.argv) > 1:
  hex_string = sys.argv[1]
  decimal_list = hex_to_dec(hex_string)
  for x in range(1, 256):
    if x not in decimal_list:
      print("\\x" + "{:02x}".format(x), end='')
else:
  print(f"Usage example: {sys.argv[0]} \"\\x00\\x01\\x02\"")
