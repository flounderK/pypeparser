#!/usr/bin/env python3
import enum


class ImageComdat(enum.IntEnum):
    IMAGE_COMDAT_SELECT_NODUPLICATES = 1
    IMAGE_COMDAT_SELECT_ANY = 2
    IMAGE_COMDAT_SELECT_SAME_SIZE = 3
    IMAGE_COMDAT_SELECT_EXACT_MATCH = 4
    IMAGE_COMDAT_SELECT_ASSOCIATIVE = 5
    IMAGE_COMDAT_SELECT_LARGEST = 6


class ImageDllCharacteristics(enum.IntFlag):
    IMAGE_DLLCHARACTERISTICS_RESERVED_1 = 0x0001
    IMAGE_DLLCHARACTERISTICS_RESERVED_2 = 0x0002
    IMAGE_DLLCHARACTERISTICS_RESERVED_4 = 0x0004
    IMAGE_DLLCHARACTERISTICS_RESERVED_8 = 0x0008
    IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA = 0x0020
    IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040
    IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY = 0x0080
    IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100
    IMAGE_DLLCHARACTERISTICS_NO_ISOLATION = 0x0200
    IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x0400
    IMAGE_DLLCHARACTERISTICS_NO_BIND = 0x0800
    IMAGE_DLLCHARACTERISTICS_APPCONTAINER = 0x1000
    IMAGE_DLLCHARACTERISTICS_WDM_DRIVER = 0x2000
    IMAGE_DLLCHARACTERISTICS_GUARD_CF = 0x4000
    IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000


class ImageFileCharacteristics(enum.IntFlag):
    IMAGE_FILE_RELOCS_STRIPPED = 0x0001
    IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002
    IMAGE_FILE_LINE_NUMS_STRIPPED = 0x0004
    IMAGE_FILE_LOCAL_SYMS_STRIPPED = 0x0008
    IMAGE_FILE_AGGRESSIVE_WS_TRIM = 0x0010
    IMAGE_FILE_LARGE_ADDRESS_AWARE = 0x0020
    IMAGE_FILE_BYTES_REVERSED_LO = 0x0080
    IMAGE_FILE_32BIT_MACHINE = 0x0100
    IMAGE_FILE_DEBUG_STRIPPED = 0x0200
    IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP = 0x0400
    IMAGE_FILE_NET_RUN_FROM_SWAP = 0x0800
    IMAGE_FILE_SYSTEM = 0x1000
    IMAGE_FILE_DLL = 0x2000
    IMAGE_FILE_UP_SYSTEM_ONLY = 0x4000
    IMAGE_FILE_BYTES_REVERSED_HI = 0x8000


class ImageFileMachineType(enum.IntFlag):
    IMAGE_FILE_MACHINE_UNKNOWN = 0x0
    IMAGE_FILE_MACHINE_AM33 = 0x1d3
    IMAGE_FILE_MACHINE_AMD64 = 0x8664
    IMAGE_FILE_MACHINE_ARM = 0x1c0
    IMAGE_FILE_MACHINE_ARM64 = 0xaa64
    IMAGE_FILE_MACHINE_ARMNT = 0x1c4
    IMAGE_FILE_MACHINE_EBC = 0xebc
    IMAGE_FILE_MACHINE_I386 = 0x14c
    IMAGE_FILE_MACHINE_IA64 = 0x200
    IMAGE_FILE_MACHINE_LOONGARCH32 = 0x6232
    IMAGE_FILE_MACHINE_LOONGARCH64 = 0x6264
    IMAGE_FILE_MACHINE_M32R = 0x9041
    IMAGE_FILE_MACHINE_MIPS16 = 0x266
    IMAGE_FILE_MACHINE_MIPSFPU = 0x366
    IMAGE_FILE_MACHINE_MIPSFPU16 = 0x466
    IMAGE_FILE_MACHINE_POWERPC = 0x1f0
    IMAGE_FILE_MACHINE_POWERPCFP = 0x1f1
    IMAGE_FILE_MACHINE_R4000 = 0x166
    IMAGE_FILE_MACHINE_RISCV32 = 0x5032
    IMAGE_FILE_MACHINE_RISCV64 = 0x5064
    IMAGE_FILE_MACHINE_RISCV128 = 0x5128
    IMAGE_FILE_MACHINE_SH3 = 0x1a2
    IMAGE_FILE_MACHINE_SH3DSP = 0x1a3
    IMAGE_FILE_MACHINE_SH4 = 0x1a6
    IMAGE_FILE_MACHINE_SH5 = 0x1a8
    IMAGE_FILE_MACHINE_THUMB = 0x1c2
    IMAGE_FILE_MACHINE_WCEMIPSV2 = 0x169


class ImageRelAmd64(enum.IntFlag):
    IMAGE_REL_AMD64_ABSOLUTE = 0x0000
    IMAGE_REL_AMD64_ADDR64 = 0x0001
    IMAGE_REL_AMD64_ADDR32 = 0x0002
    IMAGE_REL_AMD64_ADDR32NB = 0x0003
    IMAGE_REL_AMD64_REL32 = 0x0004
    IMAGE_REL_AMD64_REL32_1 = 0x0005
    IMAGE_REL_AMD64_REL32_2 = 0x0006
    IMAGE_REL_AMD64_REL32_3 = 0x0007
    IMAGE_REL_AMD64_REL32_4 = 0x0008
    IMAGE_REL_AMD64_REL32_5 = 0x0009
    IMAGE_REL_AMD64_SECTION = 0x000A
    IMAGE_REL_AMD64_SECREL = 0x000B
    IMAGE_REL_AMD64_SECREL7 = 0x000C
    IMAGE_REL_AMD64_TOKEN = 0x000D
    IMAGE_REL_AMD64_SREL32 = 0x000E
    IMAGE_REL_AMD64_PAIR = 0x000F
    IMAGE_REL_AMD64_SSPAN32 = 0x0010


class ImageRelArm64(enum.IntFlag):
    IMAGE_REL_ARM64_ABSOLUTE = 0x0000
    IMAGE_REL_ARM64_ADDR32 = 0x0001
    IMAGE_REL_ARM64_ADDR32NB = 0x0002
    IMAGE_REL_ARM64_BRANCH26 = 0x0003
    IMAGE_REL_ARM64_PAGEBASE_REL21 = 0x0004
    IMAGE_REL_ARM64_REL21 = 0x0005
    IMAGE_REL_ARM64_PAGEOFFSET_12A = 0x0006
    IMAGE_REL_ARM64_PAGEOFFSET_12L = 0x0007
    IMAGE_REL_ARM64_SECREL = 0x0008
    IMAGE_REL_ARM64_SECREL_LOW12A = 0x0009
    IMAGE_REL_ARM64_SECREL_HIGH12A = 0x000A
    IMAGE_REL_ARM64_SECREL_LOW12L = 0x000B
    IMAGE_REL_ARM64_TOKEN = 0x000C
    IMAGE_REL_ARM64_SECTION = 0x000D
    IMAGE_REL_ARM64_ADDR64 = 0x000E
    IMAGE_REL_ARM64_BRANCH19 = 0x000F
    IMAGE_REL_ARM64_BRANCH14 = 0x0010
    IMAGE_REL_ARM64_REL32 = 0x0011


class ImageRelArm(enum.IntFlag):
    IMAGE_REL_ARM_ABSOLUTE = 0x0000
    IMAGE_REL_ARM_ADDR32 = 0x0001
    IMAGE_REL_ARM_ADDR32NB = 0x0002
    IMAGE_REL_ARM_BRANCH24 = 0x0003
    IMAGE_REL_ARM_BRANCH11 = 0x0004
    IMAGE_REL_ARM_REL32 = 0x000A
    IMAGE_REL_ARM_SECTION = 0x000E
    IMAGE_REL_ARM_SECREL = 0x000F
    IMAGE_REL_ARM_MOV32 = 0x0010
    IMAGE_REL_THUMB_MOV32 = 0x0011
    IMAGE_REL_THUMB_BRANCH20 = 0x0012
    UNUSED = 0x0013
    IMAGE_REL_THUMB_BRANCH24 = 0x0014
    IMAGE_REL_THUMB_BLX23 = 0x0015
    IMAGE_REL_ARM_PAIR = 0x0016


class ImageRelBased(enum.IntEnum):
    IMAGE_REL_BASED_ABSOLUTE = 0
    IMAGE_REL_BASED_HIGH = 1
    IMAGE_REL_BASED_LOW = 2
    IMAGE_REL_BASED_HIGHLOW = 3
    IMAGE_REL_BASED_HIGHADJ = 4
    IMAGE_REL_BASED_MIPS_JMPADDR = 5
    IMAGE_REL_BASED_ARM_MOV32 = 5
    IMAGE_REL_BASED_RISCV_HIGH20 = 5
    RESERVED = 6
    IMAGE_REL_BASED_THUMB_MOV32 = 7
    IMAGE_REL_BASED_RISCV_LOW12I = 7
    IMAGE_REL_BASED_RISCV_LOW12S = 8
    IMAGE_REL_BASED_LOONGARCH32_MARK_LA = 8
    IMAGE_REL_BASED_LOONGARCH64_MARK_LA = 8
    IMAGE_REL_BASED_MIPS_JMPADDR16 = 9
    IMAGE_REL_BASED_DIR64 = 10


class ImageRelI386(enum.IntFlag):
    IMAGE_REL_I386_ABSOLUTE = 0x0000
    IMAGE_REL_I386_DIR16 = 0x0001
    IMAGE_REL_I386_REL16 = 0x0002
    IMAGE_REL_I386_DIR32 = 0x0006
    IMAGE_REL_I386_DIR32NB = 0x0007
    IMAGE_REL_I386_SEG12 = 0x0009
    IMAGE_REL_I386_SECTION = 0x000A
    IMAGE_REL_I386_SECREL = 0x000B
    IMAGE_REL_I386_TOKEN = 0x000C
    IMAGE_REL_I386_SECREL7 = 0x000D
    IMAGE_REL_I386_REL32 = 0x0014


class ImageRelIa64(enum.IntFlag):
    IMAGE_REL_IA64_ABSOLUTE = 0x0000
    IMAGE_REL_IA64_IMM14 = 0x0001
    IMAGE_REL_IA64_IMM22 = 0x0002
    IMAGE_REL_IA64_IMM64 = 0x0003
    IMAGE_REL_IA64_DIR32 = 0x0004
    IMAGE_REL_IA64_DIR64 = 0x0005
    IMAGE_REL_IA64_PCREL21B = 0x0006
    IMAGE_REL_IA64_PCREL21M = 0x0007
    IMAGE_REL_IA64_PCREL21F = 0x0008
    IMAGE_REL_IA64_GPREL22 = 0x0009
    IMAGE_REL_IA64_LTOFF22 = 0x000A
    IMAGE_REL_IA64_SECTION = 0x000B
    IMAGE_REL_IA64_SECREL22 = 0x000C
    IMAGE_REL_IA64_SECREL64I = 0x000D
    IMAGE_REL_IA64_SECREL32 = 0x000E
    IMAGE_REL_IA64_DIR32NB = 0x0010
    IMAGE_REL_IA64_SREL14 = 0x0011
    IMAGE_REL_IA64_SREL22 = 0x0012
    IMAGE_REL_IA64_SREL32 = 0x0013
    IMAGE_REL_IA64_UREL32 = 0x0014
    IMAGE_REL_IA64_PCREL60X = 0x0015
    IMAGE_REL_IA64_PCREL60B = 0x0016
    IMAGE_REL_IA64_PCREL60F = 0x0017
    IMAGE_REL_IA64_PCREL60I = 0x0018
    IMAGE_REL_IA64_PCREL60M = 0x0019
    IMAGE_REL_IA64_IMMGPREL64 = 0x001a
    IMAGE_REL_IA64_TOKEN = 0x001b
    IMAGE_REL_IA64_GPREL32 = 0x001c
    IMAGE_REL_IA64_ADDEND = 0x001F


class ImageRelSh(enum.IntFlag):
    IMAGE_REL_SH3_ABSOLUTE = 0x0000
    IMAGE_REL_SH3_DIRECT16 = 0x0001
    IMAGE_REL_SH3_DIRECT32 = 0x0002
    IMAGE_REL_SH3_DIRECT8 = 0x0003
    IMAGE_REL_SH3_DIRECT8_WORD = 0x0004
    IMAGE_REL_SH3_DIRECT8_LONG = 0x0005
    IMAGE_REL_SH3_DIRECT4 = 0x0006
    IMAGE_REL_SH3_DIRECT4_WORD = 0x0007
    IMAGE_REL_SH3_DIRECT4_LONG = 0x0008
    IMAGE_REL_SH3_PCREL8_WORD = 0x0009
    IMAGE_REL_SH3_PCREL8_LONG = 0x000A
    IMAGE_REL_SH3_PCREL12_WORD = 0x000B
    IMAGE_REL_SH3_STARTOF_SECTION = 0x000C
    IMAGE_REL_SH3_SIZEOF_SECTION = 0x000D
    IMAGE_REL_SH3_SECTION = 0x000E
    IMAGE_REL_SH3_SECREL = 0x000F
    IMAGE_REL_SH3_DIRECT32_NB = 0x0010
    IMAGE_REL_SH3_GPREL4_LONG = 0x0011
    IMAGE_REL_SH3_TOKEN = 0x0012
    IMAGE_REL_SHM_PCRELPT = 0x0013
    IMAGE_REL_SHM_REFLO = 0x0014
    IMAGE_REL_SHM_REFHALF = 0x0015
    IMAGE_REL_SHM_RELLO = 0x0016
    IMAGE_REL_SHM_RELHALF = 0x0017
    IMAGE_REL_SHM_PAIR = 0x0018
    IMAGE_REL_SHM_NOMODE = 0x8000


class ImageSectionFlags(enum.IntFlag):
    IMAGE_SCN_RESERVED_0 = 0x00000000
    IMAGE_SCN_RESERVED_1 = 0x00000001
    IMAGE_SCN_RESERVED_2 = 0x00000002
    IMAGE_SCN_RESERVED_4 = 0x00000004
    IMAGE_SCN_TYPE_NO_PAD = 0x00000008
    IMAGE_SCN_RESERVED_10 = 0x00000010
    IMAGE_SCN_CNT_CODE = 0x00000020
    IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
    IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080
    IMAGE_SCN_LNK_OTHER = 0x00000100
    IMAGE_SCN_LNK_INFO = 0x00000200
    IMAGE_SCN_RESERVED_400 = 0x00000400
    IMAGE_SCN_LNK_REMOVE = 0x00000800
    IMAGE_SCN_LNK_COMDAT = 0x00001000
    IMAGE_SCN_GPREL = 0x00008000
    IMAGE_SCN_MEM_PURGEABLE = 0x00020000
    IMAGE_SCN_MEM_16BIT = 0x00020000
    IMAGE_SCN_MEM_LOCKED = 0x00040000
    IMAGE_SCN_MEM_PRELOAD = 0x00080000
    IMAGE_SCN_ALIGN_1BYTES = 0x00100000
    IMAGE_SCN_ALIGN_2BYTES = 0x00200000
    IMAGE_SCN_ALIGN_4BYTES = 0x00300000
    IMAGE_SCN_ALIGN_8BYTES = 0x00400000
    IMAGE_SCN_ALIGN_16BYTES = 0x00500000
    IMAGE_SCN_ALIGN_32BYTES = 0x00600000
    IMAGE_SCN_ALIGN_64BYTES = 0x00700000
    IMAGE_SCN_ALIGN_128BYTES = 0x00800000
    IMAGE_SCN_ALIGN_256BYTES = 0x00900000
    IMAGE_SCN_ALIGN_512BYTES = 0x00A00000
    IMAGE_SCN_ALIGN_1024BYTES = 0x00B00000
    IMAGE_SCN_ALIGN_2048BYTES = 0x00C00000
    IMAGE_SCN_ALIGN_4096BYTES = 0x00D00000
    IMAGE_SCN_ALIGN_8192BYTES = 0x00E00000
    IMAGE_SCN_LNK_NRELOC_OVFL = 0x01000000
    IMAGE_SCN_MEM_DISCARDABLE = 0x02000000
    IMAGE_SCN_MEM_NOT_CACHED = 0x04000000
    IMAGE_SCN_MEM_NOT_PAGED = 0x08000000
    IMAGE_SCN_MEM_SHARED = 0x10000000
    IMAGE_SCN_MEM_EXECUTE = 0x20000000
    IMAGE_SCN_MEM_READ = 0x40000000
    IMAGE_SCN_MEM_WRITE = 0x80000000


class ImageSubsystem(enum.IntEnum):
    IMAGE_SUBSYSTEM_UNKNOWN = 0
    IMAGE_SUBSYSTEM_NATIVE = 1
    IMAGE_SUBSYSTEM_WINDOWS_GUI = 2
    IMAGE_SUBSYSTEM_WINDOWS_CUI = 3
    IMAGE_SUBSYSTEM_OS2_CUI = 5
    IMAGE_SUBSYSTEM_POSIX_CUI = 7
    IMAGE_SUBSYSTEM_NATIVE_WINDOWS = 8
    IMAGE_SUBSYSTEM_WINDOWS_CE_GUI = 9
    IMAGE_SUBSYSTEM_EFI_APPLICATION = 10
    IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER = 11
    IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER = 12
    IMAGE_SUBSYSTEM_EFI_ROM = 13
    IMAGE_SUBSYSTEM_XBOX = 14
    IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION = 16


class ImageSymClass(enum.IntEnum):
    IMAGE_SYM_CLASS_END_OF_FUNCTION = -1
    IMAGE_SYM_CLASS_NULL = 0
    IMAGE_SYM_CLASS_AUTOMATIC = 1
    IMAGE_SYM_CLASS_EXTERNAL = 2
    IMAGE_SYM_CLASS_STATIC = 3
    IMAGE_SYM_CLASS_REGISTER = 4
    IMAGE_SYM_CLASS_EXTERNAL_DEF = 5
    IMAGE_SYM_CLASS_LABEL = 6
    IMAGE_SYM_CLASS_UNDEFINED_LABEL = 7
    IMAGE_SYM_CLASS_MEMBER_OF_STRUCT = 8
    IMAGE_SYM_CLASS_ARGUMENT = 9
    IMAGE_SYM_CLASS_STRUCT_TAG = 10
    IMAGE_SYM_CLASS_MEMBER_OF_UNION = 11
    IMAGE_SYM_CLASS_UNION_TAG = 12
    IMAGE_SYM_CLASS_TYPE_DEFINITION = 13
    IMAGE_SYM_CLASS_UNDEFINED_STATIC = 14
    IMAGE_SYM_CLASS_ENUM_TAG = 15
    IMAGE_SYM_CLASS_MEMBER_OF_ENUM = 16
    IMAGE_SYM_CLASS_REGISTER_PARAM = 17
    IMAGE_SYM_CLASS_BIT_FIELD = 18
    IMAGE_SYM_CLASS_BLOCK = 100
    IMAGE_SYM_CLASS_FUNCTION = 101
    IMAGE_SYM_CLASS_END_OF_STRUCT = 102
    IMAGE_SYM_CLASS_FILE = 103
    IMAGE_SYM_CLASS_SECTION = 104
    IMAGE_SYM_CLASS_WEAK_EXTERNAL = 105
    IMAGE_SYM_CLASS_CLR_TOKEN = 107


class ImageSymDtype(enum.IntEnum):
    IMAGE_SYM_DTYPE_NULL = 0
    IMAGE_SYM_DTYPE_POINTER = 1
    IMAGE_SYM_DTYPE_FUNCTION = 2
    IMAGE_SYM_DTYPE_ARRAY = 3


class ImageSymType(enum.IntEnum):
    IMAGE_SYM_TYPE_NULL = 0
    IMAGE_SYM_TYPE_VOID = 1
    IMAGE_SYM_TYPE_CHAR = 2
    IMAGE_SYM_TYPE_SHORT = 3
    IMAGE_SYM_TYPE_INT = 4
    IMAGE_SYM_TYPE_LONG = 5
    IMAGE_SYM_TYPE_FLOAT = 6
    IMAGE_SYM_TYPE_DOUBLE = 7
    IMAGE_SYM_TYPE_STRUCT = 8
    IMAGE_SYM_TYPE_UNION = 9
    IMAGE_SYM_TYPE_ENUM = 10
    IMAGE_SYM_TYPE_MOE = 11
    IMAGE_SYM_TYPE_BYTE = 12
    IMAGE_SYM_TYPE_WORD = 13
    IMAGE_SYM_TYPE_UINT = 14
    IMAGE_SYM_TYPE_DWORD = 15


class ImportType(enum.IntEnum):
    IMPORT_CODE = 0
    IMPORT_DATA = 1
    IMPORT_CONST = 2


