import base64
import sys

infh = open(sys.argv[1], "r")
s = infh.read()
infh.close()

res = base64.b64decode(s)

print(res)
