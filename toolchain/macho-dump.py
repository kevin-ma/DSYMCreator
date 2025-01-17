#!/usr/bin/env python

# copy from https://llvm.org/svn/llvm-project/llvm/tags/RELEASE_28/test/Scripts/macho-dump

import struct
import sys
import StringIO

class Reader:
   def __init__(self, path):
      if path == '-':
         # Snarf all the data so we can seek.
         self.file = StringIO.StringIO(sys.stdin.read())
      else:
         self.file = open(path,'rb')
      self.isLSB = None
      self.is64Bit = None

      self.string_table = None

   def tell(self):
      return self.file.tell()

   def seek(self, pos):
      self.file.seek(pos)

   def read(self, N):
      data = self.file.read(N)
      if len(data) != N:
         raise ValueError,"Out of data!"
      return data

   def read8(self):
      return ord(self.read(1))

   def read16(self):
      return struct.unpack('><'[self.isLSB] + 'H', self.read(2))[0]

   def read32(self):
      # Force to 32-bit, if possible; otherwise these might be long ints on a
      # big-endian platform. FIXME: Why???
      Value = struct.unpack('><'[self.isLSB] + 'I', self.read(4))[0]
      return int(Value)

   def read64(self):
      return struct.unpack('><'[self.isLSB] + 'Q', self.read(8))[0]

   def registerStringTable(self, strings):
      if self.string_table is not None:
         raise ValueError,"%s: warning: multiple string tables" % sys.argv[0]

      self.string_table = strings

   def getString(self, index):
      if self.string_table is None:
         raise ValueError,"%s: warning: no string table registered" % sys.argv[0]
      
      end = self.string_table.index('\x00', index)
      return self.string_table[index:end]

def dumpmacho(path, opts):
   f = Reader(path)

   magic = f.read(4)
   if magic == '\xFE\xED\xFA\xCE':
      f.isLSB, f.is64Bit = False, False
   elif magic == '\xCE\xFA\xED\xFE':
      f.isLSB, f.is64Bit = True, False
   elif magic == '\xFE\xED\xFA\xCF':
      f.isLSB, f.is64Bit = False, True
   elif magic == '\xCF\xFA\xED\xFE':
      f.isLSB, f.is64Bit = True, True
   else:
      f.isLSB, f.is64Bit = False, True
      # print(magic)
      # raise ValueError,"Not a Mach-O object file: %r (bad magic)" % path

   # ➜  DSYMCreator git:(master) ✗ ./toolchain/DSYMCreator --uuid 91AE4831-3D40-3FCE-ABFC-17E0CB64FD26 --raw_ida_symbol /Users/bytedance/Documents/GitHub/DSYMCreator/input.txt --dwarf_section_vmbase 0x100000000 --output /Users/bytedance/Documents/GitHub/DSYMCreator/aaa --arm64
   print "('cputype', %r)" % f.read32()
   print "('cpusubtype', %r)" % f.read32()
   filetype = f.read32()
   print "('filetype', %r)" % filetype
   
   numLoadCommands = f.read32()
   print "('num_load_commands', %r)" % filetype

   loadCommandsSize = f.read32()
   print "('load_commands_size', %r)" % loadCommandsSize

   print "('flag', %r)" % f.read32()

   if f.is64Bit:
      print "('reserved', %r)" % f.read32()

   start = f.tell()

   print "('load_commands', ["
   for i in range(numLoadCommands):
      dumpLoadCommand(f, i, opts)
   print "])"

   if f.tell() - start != loadCommandsSize:
      raise ValueError,"%s: warning: invalid load commands size: %r" % (
         sys.argv[0], loadCommandsSize)

def dumpLoadCommand(f, i, opts):
   start = f.tell()

   print "  # Load Command %r" % i
   cmd = f.read32()
   print " (('command', %r)" % cmd
   cmdSize = f.read32()
   print "  ('size', %r)" % cmdSize

   if cmd == 1:
      dumpSegmentLoadCommand(f, opts, False)
   elif cmd == 2:
      dumpSymtabCommand(f, opts)
   elif cmd == 11:
      dumpDysymtabCommand(f, opts)
   elif cmd == 25:
      dumpSegmentLoadCommand(f, opts, True)
   elif cmd == 27:
      import uuid
      print "  ('uuid', %s)" % uuid.UUID(bytes=f.read(16))
   else:
      print >>sys.stderr,"%s: warning: unknown load command: %r" % (
         sys.argv[0], cmd)
      f.read(cmdSize - 8)
   print " ),"

   if f.tell() - start != cmdSize:
      raise ValueError,"%s: warning: invalid load command size: %r" % (
         sys.argv[0], cmdSize)

def dumpSegmentLoadCommand(f, opts, is64Bit):
   print "  ('segment_name', %r)" % f.read(16) 
   if is64Bit:
      print "  ('vm_addr', %r)" % f.read64()
      print "  ('vm_size', %r)" % f.read64()
      print "  ('file_offset', %r)" % f.read64()
      print "  ('file_size', %r)" % f.read64()
   else:
      print "  ('vm_addr', %r)" % f.read32()
      print "  ('vm_size', %r)" % f.read32()
      print "  ('file_offset', %r)" % f.read32()
      print "  ('file_size', %r)" % f.read32()
   print "  ('maxprot', %r)" % f.read32()
   print "  ('initprot', %r)" % f.read32()
   numSections = f.read32()
   print "  ('num_sections', %r)" % numSections
   print "  ('flags', %r)" % f.read32()

   print "  ('sections', ["
   for i in range(numSections):
      dumpSection(f, i, opts, is64Bit)
   print "  ])"

def dumpSymtabCommand(f, opts):
   symoff = f.read32()
   print "  ('symoff', %r)" % symoff
   nsyms = f.read32()
   print "  ('nsyms', %r)" % nsyms
   stroff = f.read32()
   print "  ('stroff', %r)" % stroff
   strsize = f.read32()
   print "  ('strsize', %r)" % strsize

   prev_pos = f.tell()

   f.seek(stroff)
   string_data = f.read(strsize)
   print "  ('_string_data', %r)" % string_data

   f.registerStringTable(string_data)

   f.seek(symoff)
   print "  ('_symbols', ["
   for i in range(nsyms):
      dumpNlist32(f, i, opts)
   print "  ])"
      
   f.seek(prev_pos)

def dumpNlist32(f, i, opts):
   print "    # Symbol %r" % i
   n_strx = f.read32()
   print "   (('n_strx', %r)" % n_strx
   n_type = f.read8()
   print "    ('n_type', %#x)" % n_type
   n_sect = f.read8()
   print "    ('n_sect', %r)" % n_sect
   n_desc = f.read16()
   print "    ('n_desc', %r)" % n_desc
   if f.is64Bit:
      n_value = f.read64()
      print "    ('n_value', %r)" % n_value
   else:
      n_value = f.read32()
      print "    ('n_value', %r)" % n_value
   print "    ('_string', %r)" % f.getString(n_strx)
   print "   ),"

def dumpDysymtabCommand(f, opts):   
   print "  ('ilocalsym', %r)" % f.read32()
   print "  ('nlocalsym', %r)" % f.read32()
   print "  ('iextdefsym', %r)" % f.read32()
   print "  ('nextdefsym', %r)" % f.read32()
   print "  ('iundefsym', %r)" % f.read32()
   print "  ('nundefsym', %r)" % f.read32()
   print "  ('tocoff', %r)" % f.read32()
   print "  ('ntoc', %r)" % f.read32()
   print "  ('modtaboff', %r)" % f.read32()
   print "  ('nmodtab', %r)" % f.read32()
   print "  ('extrefsymoff', %r)" % f.read32()
   print "  ('nextrefsyms', %r)" % f.read32()
   indirectsymoff = f.read32()
   print "  ('indirectsymoff', %r)" % indirectsymoff
   nindirectsyms = f.read32()
   print "  ('nindirectsyms', %r)" % nindirectsyms
   print "  ('extreloff', %r)" % f.read32()
   print "  ('nextrel', %r)" % f.read32()
   print "  ('locreloff', %r)" % f.read32()
   print "  ('nlocrel', %r)" % f.read32()

   prev_pos = f.tell()

   f.seek(indirectsymoff)
   print "  ('_indirect_symbols', ["
   for i in range(nindirectsyms):
      print "    # Indirect Symbol %r" % i
      print "    (('symbol_index', %#x),)," % f.read32()
   print "  ])"
      
   f.seek(prev_pos)

def dumpSection(f, i, opts, is64Bit):
   print "    # Section %r" % i
   print "   (('section_name', %r)" % f.read(16)
   print "    ('segment_name', %r)" % f.read(16)
   if is64Bit:
      print "    ('address', %r)" % f.read64()
      size = f.read64()
      print "    ('size', %r)" % size
   else:
      print "    ('address', %r)" % f.read32()
      size = f.read32()
      print "    ('size', %r)" % size
   offset = f.read32()
   print "    ('offset', %r)" % offset
   print "    ('alignment', %r)" % f.read32()   
   reloc_offset = f.read32()
   print "    ('reloc_offset', %r)" % reloc_offset
   num_reloc = f.read32()
   print "    ('num_reloc', %r)" % num_reloc
   print "    ('flags', %#x)" % f.read32()
   print "    ('reserved1', %r)" % f.read32()
   print "    ('reserved2', %r)" % f.read32()
   if is64Bit:
      print "    ('reserved3', %r)" % f.read32()
   print "   ),"

   prev_pos = f.tell()

   f.seek(reloc_offset)
   print "  ('_relocations', ["
   for i in range(num_reloc):
      print "    # Relocation %r" % i
      print "    (('word-0', %#x)," % f.read32()
      print "     ('word-1', %#x))," % f.read32()
   print "  ])"

   if opts.dumpSectionData:
      f.seek(offset)
      print "  ('_section_data', %r)" % f.read(size)
      
   f.seek(prev_pos)
   
def main():
    from optparse import OptionParser, OptionGroup
    parser = OptionParser("usage: %prog [options] {files}")
    parser.add_option("", "--dump-section-data", dest="dumpSectionData",
                      help="Dump the contents of sections",
                      action="store_true", default=False)    
    (opts, args) = parser.parse_args()

    if not args:
       args.append('-')

    for arg in args:
       dumpmacho(arg, opts)

if __name__ == '__main__':
   main()
