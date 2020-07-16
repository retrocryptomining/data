import sys
import base64

fh = open(sys.argv[1], "r")

for line in fh:
    if "[" in line:
        continue
    if "]" in line:
        break
    line = line.rstrip(",").strip("'")
    l = base64.b64decode(line)
    l = l.decode('utf-8')
    sys.stdout.write(l)
