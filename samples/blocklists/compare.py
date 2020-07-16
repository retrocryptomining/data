import sys
infh = open(sys.argv[1], "r")
infh_readlines = infh.readlines()
infh.close()

known = open(sys.argv[2], "r")
known_lines = known.readlines()
known.close()

for line in infh_readlines:
    if not line in known_lines:
        print(line)
