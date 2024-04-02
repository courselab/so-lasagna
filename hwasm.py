#!/usr/bin/env python3
import json
import struct
import sys

class Symbol:
    def __init__(self, offset, addend, secname):
        self.offset = offset
        self.addend = addend
        self.secname = secname

class Section:
    def __init__(self, base):
        self.base = base

class Relocation:
    def __init__(self, label, addend):
        self.label = label
        self.addend = addend

class R_386_PC8(Relocation):
    def write(self, offset, unit):
        result = offset + self.addend - unit
        if result > 0x7f or result < -0x80:
            raise RuntimeError(f"R_386_PC8: {result} is too large for a rel8")
        return [result & 0xff]

    def __len__(self):
        return 1

class R_386_16(Relocation):
    def write(self, offset, unit):
        result = offset + self.addend
        if result > 0xffff:
            raise RuntimeError(f"R_386_16: {result} is too large for an imm16")
        return [result & 0xff, (result >> 8) & 0xff]

    def __len__(self):
        return 2

# Parsing.
def preprocess(line):
    """
    Prepare a line to be handled by the parsing functions.
    """
    return line.strip()

class Register:
    def __init__(self, name):
        self.name = name

class Literal:
    def __init__(self, value):
        self.value = value

class Label:
    def __init__(self, name):
        self.name = name

class MemAccess:
    def __init__(self, offset, base):
        self.offset = offset
        self.base = base

def parse_label(line):
    """
    Parses a label and produces a label name from it.
    """
    if line[-1] == ":":
        return line[:-1]

def parse_directive(line):
    """
    Parses a directive and produces a directive tuple from it.
    """
    if line[0] != ".":
        return None
    directive = line.split()[0][1:]
    operands  = "".join(line.split()[1:]).split(",")

    return directive, operands

def parse_insn(line):
    """
    Parses a line and produces an instruction tuple from it.
    """
    mnemonic = line.split()[0]
    operands  = "".join(line.split()[1:]).split(",")

    if operands == ['']:
        operands = []

    def parse_operand(operand):
        if "(" in operand and ")" in operand:
            offset, base = operand.split("(")
            base = base.rstrip(")")

            return MemAccess(parse_operand(offset), parse_operand(base))
        match operand[0]:
            case "$":
                return Literal(int(operand[1:], 0))
            case "%":
                return Register(operand[1:].lower())
            case _:
                return Label(operand)


    op = []
    for operand in operands:
        op.append(parse_operand(operand))
        
    return mnemonic, op

# Code generation.
class Generator:
    def __init__(self):
        self.section_data = {}
        self.section_type = {}
        self.current_sect = None
        self.labels = {}
        self.relocations = []

    def create_section(self, name, ty):
        self.section_data[name] = bytearray()
        self.section_type[name] = ty

    def select_section(self, name):
        assert name in self.section_data
        self.current_sect = name

    def section_len(self):
        return len(self.section_data[self.current_sect])

    def put_data(self, data):
        self.section_data[self.current_sect].extend(data)

    def put_label(self, name):
        assert name not in self.labels
        self.labels[name] = (self.current_sect, self.section_len())

    def put_reloc(self, reloc):
        self.relocations.append((reloc, self.current_sect, self.section_len()))
        self.put_data(b"\0" * len(reloc))

    def link(self, sections):
        # Tidy up the sections.
        last_fbase = 0
        last_lbase = 0
        for section in sections:
            if "fbase" in section:
                fbase = section["fbase"]
            else:
                fbase = last_fbase

            if "lbase" in section:
                lbase = section["lbase"]
            else:
                lbase = last_lbase

            assert last_fbase <= fbase
            assert last_lbase <= lbase

            section["lbase"] = lbase
            section["fbase"] = fbase

            sect_len = len(self.section_data[section["section"]])
            last_fbase = fbase + sect_len
            last_lbase = lbase + sect_len

        # Resolve relocations.
        sectmap = dict(((x["section"], x) for x in sections))
        for reloc, reloc_sect, reloc_offset in self.relocations:
            label_sect, label_offset = self.labels[reloc.label]
            label_sect_base = sectmap[label_sect]["lbase"]

            reloc_sect_base = sectmap[reloc_sect]["lbase"]

            self.section_data[reloc_sect][reloc_offset:reloc_offset+len(reloc)] = reloc.write(
                label_sect_base + label_offset, 
                reloc_sect_base + reloc_offset)

        # Write the binary into a byte array.
        binary = bytearray()
        last_fbase = 0
        for section in sections:
            fbase = section["fbase"]

            binary.extend(b"\0" * (fbase - last_fbase))
            binary.extend(self.section_data[section["section"]])

            last_fbase = fbase + len(self.section_data[section["section"]])

        return binary

def gen_label(label, gen):
    gen.put_label(label)

def gen_directive(directive, gen):
    print(f"    -> {repr(directive)}")
    match directive[0]:
        case "code16":
            pass
        case "section":
            name, ty = directive[1]
            gen.create_section(name, ty.strip('"'))
            gen.select_section(name)
        case "asciz":
            data = "".join(directive[1]).strip('"')
            gen.put_data(data.encode("ascii"))
        case "word":
            data = int(directive[1][0], 0)
            gen.put_data(struct.pack("<H", data))
        case _:
            print(f"warning: unknown directive '{directive[0]}'")

def gen_insn(insn, gen):
    print(f"    -> {repr(insn)}")
    match insn:
        case ("movb", [Literal(value=value), Register(name="ah")]):
            gen.put_data(b"\xB4")
            gen.put_data(struct.pack("B", value))
        case ("movw", [Literal(value=value), Register(name="si")]):
            gen.put_data(b"\xBE")
            gen.put_data(struct.pack("<H", value))
        case ("movb", [
                MemAccess(offset=Label(name=name), base=Register(name="si")), 
                Register(name="al")]):
            gen.put_data(b"\x8A\x84")
            gen.put_reloc(R_386_16(name, 0))
        case ("cmpb", [Literal(value=value), Register(name="al")]):
            gen.put_data(b"\x3C")
            gen.put_data(struct.pack("B", value))
        case ("je", [Label(name=name)]):
            gen.put_data(b"\x74")
            gen.put_reloc(R_386_PC8(name, -1))
        case ("int", [Literal(value=value)]):
            gen.put_data(b"\xCD")
            gen.put_data(struct.pack("B", value))
        case ("addw", [Literal(value=value), Register(name="si")]):
            gen.put_data(b"\x83\xC6")
            gen.put_data(struct.pack("B", value))
        case ("jmp", [Label(name=name)]):
            gen.put_data(b"\xEB")
            gen.put_reloc(R_386_PC8(name, -1))
        case ("hlt", _):
            gen.put_data(b"\xF4")
        case _:
            print("warning: unknown instruction")


def generate(source, out, linkmap):
    gen = Generator()

    # Generate the object code.
    for line in source.splitlines():
        line = preprocess(line)
        if line == "":
            continue
        print(line)

        label = parse_label(line)
        if label:
            gen_label(label, gen)
            continue

        directive = parse_directive(line)
        if directive:
            gen_directive(directive, gen)
            continue

        insn = parse_insn(line)
        gen_insn(insn, gen)

    # At this point, the generator contains all the object code in the program,
    # and we have to link it in order to produce the final binary.
    binary = gen.link(linkmap)
    out.write(binary)

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <input.asm> <linkmap.json> <output.bin>")
        sys.exit(1)

    print(f"Using input:   {sys.argv[1]}")
    print(f"Using linkmap: {sys.argv[2]}")
    print(f"Writing to:    {sys.argv[3]}")

    source = open(sys.argv[1], "r").read()
    out = open(sys.argv[3], "wb")
    linkmap = json.load(open(sys.argv[2], "r"))

    generate(source, out, linkmap)
