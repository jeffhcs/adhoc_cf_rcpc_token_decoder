
#
# Codeforces Ad Hoc RCPC Token Decoder
# Author: prophet
# Date: 2020/07/14
#

import modified_slow_aes as AES
import urllib.request
import re

#get codeforces raw response of redirect page
def get_raw_cf_response():
    return str(urllib.request.urlopen("http://codeforces.com").read())

#parse the cipher from codeforces raw response
def parse_cipher(raw_response):
    reg = "c=toNumbers\(.*?\)"
    match = re.findall(reg, raw_response)[0]
    match = match.replace("c=toNumbers(\"", "")
    match = match.replace("\")", "")
    return match

#convert hex string to byte array
def hex_to_bytes(hex_in):
    cipher = []
    for i in range(16):
        byte = int(hex_in[i*2:i*2+2], 16)
        cipher.append(byte)
    return cipher

#decode cipher array using slow aes
def cipher_decode(ciph):
    aes = AES.AESModeOfOperation()
    cypherkey = [233,238,75,3,193,208,130,41,135,24,93,39,188,162,51,120]
    iv = [24,143,175,219,224,248,126,240,252,40,16,213,179,227,71,5]
    mode = 2
    orig_len = 16
    ciph = [141,210,25,110,199,108,203,146,199,49,164,31,144,248,70,215]
    decr = aes.decrypt(ciph, orig_len, mode, cypherkey, aes.aes.keySize["SIZE_128"], iv)
    return decr

#convert decoded token into hex
def bytes_to_hex(byte_array):
    token = ""
    for byte in byte_array:
        raw_hex = hex(byte)[2:].zfill(2)
        token += raw_hex
    return token

raw_response = get_raw_cf_response()
raw_cipher = parse_cipher(raw_response)

print(f"Cipher: {raw_cipher}")

cipher_array = hex_to_bytes(raw_cipher)
decoded = cipher_decode(cipher_array)

token = bytes_to_hex(decoded)

print(f"Token : {token}")

