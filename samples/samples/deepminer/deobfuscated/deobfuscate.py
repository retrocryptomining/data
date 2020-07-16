import base64
import re
import sys
from Crypto.Cipher import AES

fh = open(sys.argv[1], "r")
js = fh.read()
fh.close()

r = re.compile('eval\(deAES\((.*)\)\);')

encrypted_part = r.search(js).group(1)


key, ciphertext = encrypted_part.split(",")

key = key.strip('"').strip()
ciphertext = ciphertext.strip().strip('"').strip()

cipher = AES.new(key, AES.MODE_ECB)
decoded = base64.b64decode(ciphertext)
decrypted = cipher.decrypt(decoded)

print(str(decrypted, 'utf-8'))
