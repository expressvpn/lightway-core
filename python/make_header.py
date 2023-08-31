
#
# Lightway Core
# Copyright (C) 2021 Express VPN International Ltd.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

import sys

from textx import metamodel_from_file

c_header = metamodel_from_file("c-header.tx")

FunDecl = c_header["FunDecl"]
PreProcessorDirective = c_header["PreProcessorDirective"]

ENDIF_HE_H = "#endif  // HE_H"


def print_fundecl(fundecl):
    if "*" in fundecl.type:
        fundecl.type = fundecl.type[:-1] + " *"
    else:
        fundecl.type = fundecl.type + " "
    if fundecl.attr:
        fundecl.attr = fundecl.attr + "\n"
    else:
        fundecl.attr = ""

    if fundecl.doc:
        print(
            "%s\n%s%s%s(%s);\n"
            % (fundecl.doc, fundecl.attr, fundecl.type, fundecl.name, fundecl.parms)
        )
    else:
        print(
            "%s%s%s(%s);\n" % (fundecl.attr, fundecl.type, fundecl.name, fundecl.parms)
        )

def print_preproc(preproc):
    if preproc.doc:
        print("%s\n#%s %s\n"
              % (preproc.doc, preproc.keyword, preproc.content)
              )
    else:
        print("#%s %s\n" % (statement.keyword, statement.content))

include_header = sys.argv[1]
print("Including header", include_header, file=sys.stderr)

for line in open(include_header):
    if not line.startswith(ENDIF_HE_H):
        print(line, end="")

for header in sys.argv[2:]:
    print("Processing header file", header, file=sys.stderr)
    program = c_header.model_from_file(header)
    for statement in program.statements:
        if isinstance(statement, PreProcessorDirective) and "include" not in statement.keyword and "_H" not in statement.content:
            print_preproc(statement)
        if isinstance(statement, FunDecl) and "internal" not in statement.name:
            print_fundecl(statement)

print(ENDIF_HE_H, end="\n")
