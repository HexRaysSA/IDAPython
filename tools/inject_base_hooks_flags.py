from __future__ import print_function

import re
import string
from argparse import ArgumentParser

parser = ArgumentParser()
parser.add_argument("-i", "--input", required=True)
parser.add_argument("-o", "--output", required=True)
parser.add_argument("-f", "--file-with-flags", required=True)
args = parser.parse_args()

with open(args.input) as fin:
    template = string.Template(fin.read())

with open(args.file_with_flags) as fin:
    raw = fin.read()
pat = re.compile(r"^#\s*define\s+(HBF_[A-Za-z0-9_]*)\s+([0-9x]*)\s*(.*)$")
decls = []
for line in raw.split("\n"):
    m = pat.match(line)
    if m:
        decls.append(line)
kvps = {
    "BASE_HOOKS_FLAGS" : "\n".join(decls)
}

with open(args.output, "w") as fout:
    fout.write(template.substitute(kvps))

