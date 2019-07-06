#!/usr/bin/env python
# Barely-tested port of
# https://github.com/radare/radare2/blob/e8f80a165c7dd89d955a1ee7f432bd9a1ba88976/libr/anal/flirt.c

from __future__ import print_function
from . import binrw
from . import crc
from builtins import range, bytes, zip
try:
    from typing import List
except ImportError:
    pass
from itertools import islice
try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO
import zlib
import logging
import sys
import re

logging.basicConfig()
log = logging.getLogger(__name__)
# log.setLevel(logging.DEBUG)
mlog = logging.getLogger(__name__ + '_match')
# mlog.setLevel(logging.DEBUG)


FLIRT_NAME_MAX = 1024


def list2hexstring(ll):
    return ''.join(['{:02X}'.format(l) for l in ll])


def pattern2string(pp, mask_array):
    if pp is None:
        return ''
    return ''.join(['{:02X}'.format(p) if not m else '..' for p, m in zip(pp, mask_array)])


def read_max_2_bytes(f):
    b = binrw.read_u8(f)
    if b & 0x80 == 0x80:
        return ((b & 0x7F) << 8) | binrw.read_u8(f)
    else:
        return b


def read_multiple_bytes(f):
    b = binrw.read_u8(f)
    if b & 0x80 != 0x80:
        return b
    elif b & 0xC0 != 0xC0:
        return ((b & 0x7F) << 8) | binrw.read_u8(f)
    elif b & 0xE0 != 0xE0:
        return ((b & 0x3F) << 24) | binrw.read_u24be(f)
    else:
        return binrw.read_u32be(f)


def read_node_variant_mask(f, length):
    if length < 0x10:
        return read_max_2_bytes(f)
    elif length <= 0x20:
        return read_multiple_bytes(f)
    elif length <= 0x40:
        return (read_multiple_bytes(f) << 32) | read_multiple_bytes(f)
    else:
        raise FlirtException('Wrong node variant mask length: {}'.format(length))


def read_node_bytes(f, length, variant_mask):
    mask_bit = 1 << length - 1
    variant_bools = list()
    pattern = list()
    for i in range(length):
        curr_mask_bool = variant_mask & mask_bit != 0
        if curr_mask_bool:
            pattern.append(0)
        else:
            pattern.append(binrw.read_u8(f))
        variant_bools.append(curr_mask_bool)
        mask_bit >>= 1
    return variant_bools, pattern


class FlirtArch(object):
    ARCH_386 = 0          # Intel 80x86
    ARCH_Z80 = 1          # 8085, Z80
    ARCH_I860 = 2         # Intel 860
    ARCH_8051 = 3         # 8051
    ARCH_TMS = 4          # Texas Instruments TMS320C5x
    ARCH_6502 = 5         # 6502
    ARCH_PDP = 6          # PDP11
    ARCH_68K = 7          # Motoroal 680x0
    ARCH_JAVA = 8         # Java
    ARCH_6800 = 9         # Motorola 68xx
    ARCH_ST7 = 10         # SGS-Thomson ST7
    ARCH_MC6812 = 11      # Motorola 68HC12
    ARCH_MIPS = 12        # MIPS
    ARCH_ARM = 13         # Advanced RISC Machines
    ARCH_TMSC6 = 14       # Texas Instruments TMS320C6x
    ARCH_PPC = 15         # PowerPC
    ARCH_80196 = 16       # Intel 80196
    ARCH_Z8 = 17          # Z8
    ARCH_SH = 18          # Renesas (formerly Hitachi) SuperH
    ARCH_NET = 19         # Microsoft Visual Studio.Net
    ARCH_AVR = 20         # Atmel 8-bit RISC processor(s)
    ARCH_H8 = 21          # Hitachi H8/300, H8/2000
    ARCH_PIC = 22         # Microchip's PIC
    ARCH_SPARC = 23       # SPARC
    ARCH_ALPHA = 24       # DEC Alpha
    ARCH_HPPA = 25        # Hewlett-Packard PA-RISC
    ARCH_H8500 = 26       # Hitachi H8/500
    ARCH_TRICORE = 27     # Tasking Tricore
    ARCH_DSP56K = 28      # Motorola DSP5600x
    ARCH_C166 = 29        # Siemens C166 family
    ARCH_ST20 = 30        # SGS-Thomson ST20
    ARCH_IA64 = 31        # Intel Itanium IA64
    ARCH_I960 = 32        # Intel 960
    ARCH_F2MC = 33        # Fujistu F2MC-16
    ARCH_TMS320C54 = 34   # Texas Instruments TMS320C54xx
    ARCH_TMS320C55 = 35   # Texas Instruments TMS320C55xx
    ARCH_TRIMEDIA = 36    # Trimedia
    ARCH_M32R = 37        # Mitsubishi 32bit RISC
    ARCH_NEC_78K0 = 38    # NEC 78K0
    ARCH_NEC_78K0S = 39   # NEC 78K0S
    ARCH_M740 = 40        # Mitsubishi 8bit
    ARCH_M7700 = 41       # Mitsubishi 16bit
    ARCH_ST9 = 42         # ST9+
    ARCH_FR = 43          # Fujitsu FR Family
    ARCH_MC6816 = 44      # Motorola 68HC16
    ARCH_M7900 = 45       # Mitsubishi 7900
    ARCH_TMS320C3 = 46    # Texas Instruments TMS320C3
    ARCH_KR1878 = 47      # Angstrem KR1878
    ARCH_AD218X = 48      # Analog Devices ADSP 218X
    ARCH_OAKDSP = 49      # Atmel OAK DSP
    ARCH_TLCS900 = 50     # Toshiba TLCS-900
    ARCH_C39 = 51         # Rockwell C39
    ARCH_CR16 = 52        # NSC CR16
    ARCH_MN102L00 = 53    # Panasonic MN10200
    ARCH_TMS320C1X = 54   # Texas Instruments TMS320C1x
    ARCH_NEC_V850X = 55   # NEC V850 and V850ES/E1/E2
    ARCH_SCR_ADPT = 56    # Processor module adapter for processor modules written in scripting languages
    ARCH_EBC = 57         # EFI Bytecode
    ARCH_MSP430 = 58      # Texas Instruments MSP430
    ARCH_SPU = 59         # Cell Broadband Engine Synergistic Processor Unit
    ARCH_DALVIK = 60      # Android Dalvik Virtual Machine


class FlirtFileType(object):
    FILE_DOS_EXE_OLD = 0x00000001
    FILE_DOS_COM_OLD = 0x00000002
    FILE_BIN         = 0x00000004
    FILE_DOSDRV      = 0x00000008
    FILE_NE          = 0x00000010
    FILE_INTELHEX    = 0x00000020
    FILE_MOSHEX      = 0x00000040
    FILE_LX          = 0x00000080
    FILE_LE          = 0x00000100
    FILE_NLM         = 0x00000200
    FILE_COFF        = 0x00000400
    FILE_PE          = 0x00000800
    FILE_OMF         = 0x00001000
    FILE_SREC        = 0x00002000
    FILE_ZIP         = 0x00004000
    FILE_OMFLIB      = 0x00008000
    FILE_AR          = 0x00010000
    FILE_LOADER      = 0x00020000
    FILE_ELF         = 0x00040000
    FILE_W32RUN      = 0x00080000
    FILE_AOUT        = 0x00100000
    FILE_PILOT       = 0x00200000
    FILE_DOS_EXE     = 0x00400000
    FILE_DOS_COM     = 0x00800000
    FILE_AIXAR       = 0x01000000


class FlirtOsType(object):
    OS_MSDOS   = 0x01
    OS_WIN     = 0x02
    OS_OS2     = 0x04
    OS_NETWARE = 0x08
    OS_UNIX    = 0x10
    OS_OTHER   = 0x20


class FlirtAppType(object):
    APP_CONSOLE         = 0x0001
    APP_GRAPHICS        = 0x0002
    APP_EXE             = 0x0004
    APP_DLL             = 0x0008
    APP_DRV             = 0x0010
    APP_SINGLE_THREADED = 0x0020
    APP_MULTI_THREADED  = 0x0040
    APP_16_BIT          = 0x0080
    APP_32_BIT          = 0x0100
    APP_64_BIT          = 0x0200


class FlirtFeatureFlag(object):
    FEATURE_STARTUP       = 0x01
    FEATURE_CTYPE_CRC     = 0x02
    FEATURE_2BYTE_CTYPE   = 0x04
    FEATURE_ALT_CTYPE_CRC = 0x08
    FEATURE_COMPRESSED    = 0x10


class FlirtParseFlag(object):
    PARSE_MORE_PUBLIC_NAMES          = 0x01
    PARSE_READ_TAIL_BYTES            = 0x02
    PARSE_READ_REFERENCED_FUNCTIONS  = 0x04
    PARSE_MORE_MODULES_WITH_SAME_CRC = 0x08
    PARSE_MORE_MODULES               = 0x10


class FlirtFunctionFlag(object):
    FUNCTION_LOCAL = 0x02                 # describes a static function
    FUNCTION_UNRESOLVED_COLLISION = 0x08  # describes a collision that wasn't resolved


class FlirtException(Exception):
    pass


class FlirtFunction(object):
    def __init__(self, name, offset, negative_offset, is_local, is_collision):
        self.name = name
        self.offset = offset
        self.negative_offset = negative_offset
        self.is_local = is_local
        self.is_collision = is_collision

    def __str__(self):
        return '<{}: name={}, offset=0x{:04X}, negative_offset={}, is_local={}, is_collision={}>'.format(
            self.__class__.__name__, self.name, self.offset, self.negative_offset, self.is_local, self.is_collision
        )


class FlirtTailByte(object):
    def __init__(self, offset, value):
        self.offset = offset
        self.value = value


class FlirtModule(object):
    def __init__(self, crc_length, crc16, length, public_functions, tail_bytes, referenced_functions):
        # type: (int, int, int, List[FlirtFunction], List[FlirtTailByte], List[FlirtFunction]) -> ()
        self.crc_length = crc_length
        self.crc16 = crc16
        self.length = length
        self.public_functions = public_functions
        self.tail_bytes = tail_bytes
        self.referenced_functions = referenced_functions


class FlirtNode(object):
    def __init__(self, children, modules, length, variant_mask, pattern):
        self.children = children
        self.modules = modules
        self.length = length
        self.variant_mask = variant_mask
        self.pattern = pattern

    @property
    def is_leaf(self):
        return len(self.children) == 0

    def __str__(self):
        return '<{}: children={}, modules={}, length={}, variant={}, pattern="{}">'.format(
            self.__class__.__name__, len(self.children), len(self.modules), self.length, self.variant_mask
            , pattern2string(self.pattern, self.variant_mask)
        )


class FlirtHeader(object):
    def __init__(self, version, arch, file_types, os_types, app_types, features, old_n_functions, crc16, ctype
                 , ctypes_crc16, n_functions, pattern_size, ctype_unk, library_name):
        self.version = version
        self.arch = arch
        self.file_types = file_types
        self.os_types = os_types
        self.app_types = app_types
        self.features = features
        self.old_n_functions = old_n_functions
        self.crc16 = crc16
        self.ctype = ctype
        self.ctypes_crc16 = ctypes_crc16
        self.n_functions = n_functions
        self.pattern_size = pattern_size
        self.ctype_unk = ctype_unk
        self.library_name = library_name


class FlirtFile(object):
    def __init__(self, header, root):
        # type: (FlirtHeader, FlirtNode) -> ()
        self.header = header
        self.root = root


def parse_header(f):
    # type: (file) -> (FlirtHeader)
    magic = f.read(6)
    if magic != b'IDASGN':
        raise FlirtException('Wrong file type')

    version = binrw.read_u8(f)
    if version < 5 or version > 10:
        raise FlirtException('Unknown version: {}'.format(version))

    arch = binrw.read_u8(f)
    file_types = binrw.read_u32le(f)
    os_types = binrw.read_u16le(f)
    app_types = binrw.read_u16le(f)
    features = binrw.read_u16le(f)
    old_n_functions = binrw.read_u16le(f)
    crc16 = binrw.read_u16le(f)
    ctype = f.read(12)
    library_name_len = binrw.read_u8(f)
    ctypes_crc16 = binrw.read_u16le(f)

    n_functions = None
    pattern_size = None
    ctype_unk = None
    if version >= 6:
        n_functions = binrw.read_u32le(f)

        if version >= 8:
            pattern_size = binrw.read_u16le(f)

            if version >= 10:
                ctype_unk = binrw.read_u16le(f)

    library_name = f.read(library_name_len)

    return FlirtHeader(version, arch, file_types, os_types, app_types, features, old_n_functions, crc16, ctype
                       , ctypes_crc16, n_functions, pattern_size, ctype_unk, library_name)


def parse_tail_byte(f, version):
    if version >= 9:
        offset = read_multiple_bytes(f)
    else:
        offset = read_max_2_bytes(f)
    value = binrw.read_u8(f)
    log.debug('Tail byte: 0x{:02X} @ 0x{:04X}'.format(value, offset))
    return FlirtTailByte(offset, value)


def parse_tail_bytes(f, version):
    if version >= 8:
        length = binrw.read_u8(f)
    else:
        length = 1
    tail_bytes = []
    for i in range(length):
        tail_bytes.append(parse_tail_byte(f, version))
    return tail_bytes


def parse_referenced_function(f, version):
    if version >= 9:
        offset = read_multiple_bytes(f)
    else:
        offset = read_max_2_bytes(f)

    name_length = binrw.read_u8(f)
    if name_length == 0:
        name_length = read_multiple_bytes(f)

    if name_length & 0x80000000 != 0:  # (int) name_length < 0
        raise FlirtException('Negative name length')

    name = list()
    for i in range(name_length):
        name.append(binrw.read_u8(f))

    negative_offset = False
    if name[-1] == 0:
        name = name[:-1]
        negative_offset = True

    name = bytearray(name).decode('ascii')
    log.debug('Referenced function: "{}" @ 0x{:04X}'.format(name, offset))
    return FlirtFunction(name, offset, negative_offset, False, False)


def parse_referenced_functions(f, version):
    if version >= 8:
        length = binrw.read_u8(f)
    else:
        length = 1

    referenced_functions = []
    for i in range(length):
        referenced_functions.append(parse_referenced_function(f, version))
    return referenced_functions


def parse_public_function(f, version, offset):
    is_local = False
    is_collision = False

    if version >= 9:
        offset += read_multiple_bytes(f)
    else:
        offset += read_max_2_bytes(f)

    b = binrw.read_u8(f)
    if b < 0x20:
        if b & FlirtFunctionFlag.FUNCTION_LOCAL:
            is_local = True
        if b & FlirtFunctionFlag.FUNCTION_UNRESOLVED_COLLISION:
            is_collision = True
        if b & 0x01 or b & 0x04:
            log.debug('Investigate public name flag: 0x{:02X} @ 0x{:04X}'.format(b, offset))
        b = binrw.read_u8(f)

    name = list()
    name_finished = False
    for i in range(FLIRT_NAME_MAX):
        if b < 0x20:
            name_finished = True
            break

        name.append(b)
        b = binrw.read_u8(f)
    flags = b

    name = bytearray(name).decode('ascii')
    if not name_finished:
        log.info('Function name too long: {}'.format(name))

    log.debug('Function "{}" @ 0x{:04X}'.format(name, offset))
    return FlirtFunction(name, offset, False, is_local, is_collision), offset, flags


def parse_module(f, version, crc_length, crc16):
    if version >= 9:
        length = read_multiple_bytes(f)
    else:
        length = read_max_2_bytes(f)
    # assert length < 0x8000    # According to radare2's docs, this should be true, but in my test file it's not :/

    public_fuctions = []
    offset = 0
    while True:
        func, offset, flags = parse_public_function(f, version, offset)
        public_fuctions.append(func)

        if flags & FlirtParseFlag.PARSE_MORE_PUBLIC_NAMES == 0:
            break

    tail_bytes = []
    if flags & FlirtParseFlag.PARSE_READ_TAIL_BYTES != 0:
        tail_bytes = parse_tail_bytes(f, version)

    referenced_functions = []
    if flags & FlirtParseFlag.PARSE_READ_REFERENCED_FUNCTIONS != 0:
        referenced_functions = parse_referenced_functions(f, version)

    log.debug('Module length: {}'.format(length))
    return FlirtModule(crc_length, crc16, length, public_fuctions, tail_bytes, referenced_functions), flags


def parse_modules(f, version):
    modules = list()
    while True:
        crc_length = binrw.read_u8(f)
        crc16 = binrw.read_u16be(f)

        while True:
            module, flags = parse_module(f, version, crc_length, crc16)
            modules.append(module)
            if flags & FlirtParseFlag.PARSE_MORE_MODULES_WITH_SAME_CRC == 0:
                break

        if flags & FlirtParseFlag.PARSE_MORE_MODULES == 0:
            break
    return modules


def parse_tree(f, version, is_root):
    if is_root:
        length = 0
        variant_mask = None
        pattern = None
    else:
        length = binrw.read_u8(f)
        variant_mask = read_node_variant_mask(f, length)
        variant_mask, pattern = read_node_bytes(f, length, variant_mask)

        log.debug('node = length={}, pattern="{}"'.format(
            length, pattern2string(pattern, variant_mask))
        )

    nodes = read_multiple_bytes(f)
    if nodes == 0:
        log.debug('leaf')
        modules = parse_modules(f, version)
        return FlirtNode([], modules, length, variant_mask, pattern)

    children = list()
    for i in range(nodes):
        children.append(parse_tree(f, version, False))

    return FlirtNode(children, [], length, variant_mask, pattern)


def parse_flirt_sig_file(f):
    # type: (file) -> FlirtFile
    header = parse_header(f)
    log.debug("Version: {}".format(header.version))
    if header.features & FlirtFeatureFlag.FEATURE_COMPRESSED:
        if header.version == 5:
            raise FlirtException('Compression in unsupported on flirt v5')
        f = StringIO(zlib.decompress(f.read()))

    tree = parse_tree(f, header.version, is_root=True)

    assert len(f.read(1)) == 0  # Have we read all the file?
    return FlirtFile(header, tree)

def parse_flirt_pat_file(f):
    header=None;
    length = 0
    variant_mask = None
    pattern = None
    children=list()
    root=FlirtNode(children, [], length, variant_mask, pattern)
    tree=parse_pat_tree(f,root)
    f.close()
    return FlirtFile(header, root)

def parse_pat_tree(f,root):
    lines=f.readlines()
    node_stack=[]
    node_stack.append(root)
    for line in lines:
        level= parse_line(line)
        if level>=1:
            while len(node_stack)>level:
                node_stack.pop()
            line=line.strip()[:-1]
            length=len(line)
            variant_mask=parse_pat_variant(line)
            pattern=line.replace('.','0')
            node=FlirtNode(list(), [], length, variant_mask, pattern)
            root_node=node_stack[-1]
            root_node.children.append(node)
            node_stack.append(node)
        else:
            module=parse_pat_modules(line)
            root_node=node_stack[-1]
            root_node.modules.append(module)

def parse_line(line):
    if not line.endswith(':\r\n'):
        return -1
    count=0
    for c in line:
        if c==' ':
            count+=1
    count=count/2
    return count+1

def parse_pat_modules(line):
    module_line=line.lstrip().split(" ")
    functions=list()
    function=FlirtFunction(module_line[4],None,None,None,None)
    functions.append(function)
    return FlirtModule(int(module_line[1],16),int(module_line[2],16),int(module_line[3],16),functions,None,None)

def parse_pat_variant(line):
    variant_mask=list()
    i=-1
    for c in line:
        i+=1
        if i%2==0:
            continue
        if c=='.':
            variant_mask.append(True)
        else:
            variant_mask.append(False)
    return variant_mask

def match_node_pattern(node, buff,length,is_root):
    # type: (FlirtNode, bytes, int) -> bool
    assert len(buff)  >= 0
    # Check if we have enough data
    if len(buff) <  len(node.pattern):
        return False
    length=length/2
    buff=bytearray.fromhex(buff)
    pattern=bytearray.fromhex(node.pattern)
    miss_count=0.0
    match_count=0.0
    variant_count=0.0
    for i, (b, p, v) in enumerate(zip(islice(buff, length,len(buff)),pattern, node.variant_mask)):
        #print("DEBUG match node pattern b {0} p {1} v {2}".format(b,p,v))
        #print('found prefix: {}'.format(pattern2string(node.pattern, node.variant_mask)))
        match_count+=1
        if v:
            variant_count+=1
            continue
        elif b != p and b!=p-1 and b!=p+1:
            if is_root:
                return False
            miss_count+=1
            continue
    #print("DEBUG miss count {0}  match count {1}".format(miss_count,match_count))
    miss_rate=miss_count/match_count
    unknown_rate=variant_count/match_count
    if miss_rate >= 0.2 or unknown_rate>=0.5:
        return False
    return True


def match_function(sig,func_hex):
    if len(func_hex) <=0:
        return (False,None)
    #print("DEBUG match function func hex "+func_hex)
    for child in sig.root.children:
        match_result=match_node_function(child,func_hex,0,True)
        if match_result[0]:
            return match_result
    return (False,None)

def match_node_function(node,func_bytes,length,is_root):
    if match_node_pattern(node, func_bytes,length,is_root):
        #print("DEBUG match a pattern")
        if len(node.modules)>0:
            return match_modules(node.modules)
        for child in node.children:
            match_result=match_node_function(child,func_bytes,node.length+length,False)
            if match_result[0]:
                return match_result
    return (False,None)
def match_modules(modules):
    func_names=list()
    for module in modules:
        for funk in module.public_functions:
            if "\r\n" in funk.name:
                funk.name=re.findall(r":(.+?)\r\n",funk.name)[0]
            elif "." in funk.name:
                if len(re.findall(r":(.*)",funk.name))>0:
                    funk.name=re.findall(r":(.*)",funk.name)[0]
            func_names.append(funk.name)
    '''if module.crc_length<len(func_bytes) and module.crc16!=crc.crc16(func_bytes[0:module.crc_length]):
        print("the crc is wrong")
        return (False,None)
    for tb in module.tail_bytes:
        if module.crc_length + tb.offset < buff_size \
                and buff[offset+module.crc_length+tb.offset] != tb.value:
            mlog.debug('Tail: {:02X} - {:02X}'.format(tb.value, buff[offset+module.crc_length+tb.offset]))
            print("the tb value is wrong")
            return (False,None)'''
    return (True,func_names)

