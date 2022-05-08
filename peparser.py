#!/usr/bin/env python3
import ctypes
from ctypes import Structure, c_ubyte, c_uint8, c_uint16, c_uint32, c_uint64, byref, memmove, cast, POINTER, addressof, BigEndianStructure, LittleEndianStructure, sizeof, Union, string_at, create_string_buffer
import struct
from struct import unpack_from
import os
import enum
import _ctypes
from collections import defaultdict


class PEEndian(enum.IntEnum):
    NONE_ENDIAN = 0
    LITTLE_ENDIAN = 1
    BIG_ENDIAN = 2


class PEHdrType(enum.IntEnum):
    PE32 = 0x10b
    ROM = 0x107
    PE32_P = 0x20b


class ImageFileMachineType(enum.IntEnum):
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


class ImageFileDLLCharacteristics(enum.IntFlag):
    IMAGE_DLLCHARACTERISTICS_NONE = 0x0000
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


class ImageFileSubsystem(enum.IntEnum):
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


class ImageFileSectionFlags(enum.IntFlag):
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


class COFFHdr(Structure):
    _fields_ = [
        ('signature', ctypes.c_uint32),
        ('machine', ctypes.c_ushort),
        ('num_sections', ctypes.c_ushort),
        ('timedatestamp', ctypes.c_uint),
        ('sym_tab_ptr', ctypes.c_uint),
        ('sym_tab_no', ctypes.c_uint),
        ('opt_hdr_sz', ctypes.c_ushort),
        ('characteristics', ctypes.c_ushort)
    ]


def write_into_ctype(ctype, bytevals):
    """
    Write bytes directly into a ctype.
    Copy byte values from bytevals into the current backing of
    the object
    """
    mutable_bytevals = bytearray(bytevals)
    sizeof_self = sizeof(ctype)
    backing_class = (c_ubyte * sizeof_self)
    # backing = backing_class.from_buffer(self)

    # temporary backing that will hold the values c
    temp_backing = backing_class.from_buffer(mutable_bytevals)
    memmove(byref(ctype), temp_backing, sizeof_self)


def get_dict_from_ctype_struct(ctype):
    return {k: getattr(ctype, k) for k, v in ctype._fields_}


def is_zeroed_ctype(ctype):
    type_bytes = bytes(ctype)
    if len(set(type_bytes)) == 1 and type_bytes[0] == 0:
        return True
    return False


class NiceHexFieldRepr:
    """
    Class to Insert a readable repr to improve debugging
    """
    def __repr__(self):
        repr_map = None
        if hasattr(self, '__repr_map__'):
            repr_map = self.__repr_map__

        ret = []
        for x in self._fields_:
            k, v = x[:2]
            attr = getattr(self, k)
            if repr_map is not None and k in repr_map.keys():
                rep_func = repr_map.get(k)
                ret.append("%s: %s" % (k, rep_func(attr)))
            elif issubclass(v, _ctypes._SimpleCData):
                ret.append("%s: %#x" % (k, attr))
            else:
                ret.append("%s: %s" % (k, bytes(attr)))
        return "\n".join(ret)


def create_pe_structures(petype=PEHdrType.PE32,
                                  endian=PEEndian.LITTLE_ENDIAN,
                                  additional_bases=None):
    """
    This function serves as a factory for all of the structure types
    for parsing a typical pe file. It also supports injecting additional
    functionality in all of the output struct types by adding a new base type
    to them.
    """
    structs = {}
    if endian == PEEndian.LITTLE_ENDIAN:
        structure_type = LittleEndianStructure
        union_type = Union
    elif endian == PEEndian.BIG_ENDIAN:
        structure_type = BigEndianStructure
        union_type = Union
    else:
        raise Exception("InvalidEndian")

    if petype == PEHdrType.PE32:
        ptr_size = 4
        ptr_type = c_uint32
        sizet_type = c_uint32
    elif petype == PEHdrType.PE32_P:
        ptr_size = 8
        ptr_type = c_uint64
        sizet_type = c_uint64
    else:
        raise Exception("Invalid PE type")

    structs['size_t'] = sizet_type
    base_types = (structure_type,)
    if additional_bases is not None:
        base_types = base_types + additional_bases

    base_union_types = (union_type,)

    # TODO: signature doesn't appear in object files
    fields = list({
        'signature': c_uint32,
        'machine': c_uint16,
        'num_sections': c_uint16,
        'timedatestamp': c_uint32,
        'sym_tab_ptr': c_uint32,
        'sym_tab_no': c_uint32,
        'opt_hdr_sz': c_uint16,
        'characteristics': c_uint16
    }.items())
    structs['COFFHdr'] = type('COFFHdr', base_types, {'_fields_': fields})

    fields = {
        'magic': c_uint16,
        'major_linker_version': c_uint8,
        'minor_linker_version': c_uint8,
        'code_sz': c_uint32,
        'initialized_data_sz': c_uint32,
        'uninitialized_data_sz': c_uint32,
        'address_of_entry': c_uint32,
        'base_of_code': c_uint32,
    }
    if petype == PEHdrType.PE32:
        fields['base_of_data'] = c_uint32
    fields = list(fields.items())
    structs['StandardCOFFData'] = type('StandardCOFFData',
                                       base_types,
                                       {'_fields_': fields})

    fields = list({
        'imagebase': sizet_type,
        'section_alignment': c_uint32,
        'file_alignment': c_uint32,
        'major_os_version': c_uint16,
        'minor_os_version': c_uint16,
        'major_image_version': c_uint16,
        'minor_image_version': c_uint16,
        'major_subsystem_version': c_uint16,
        'minor_subsystem_version': c_uint16,
        'win32_version_value': c_uint32,
        'image_sz': c_uint32,
        'headers_sz': c_uint32,
        'checksum': c_uint32,
        'subsystem': c_uint16,
        'dll_characteristics': c_uint16,
        'stack_reserve_sz': sizet_type,
        'stack_commit_sz': sizet_type,
        'heap_reserve_sz': sizet_type,
        'heap_commit_sz': sizet_type,
        'loader_flags': c_uint32,
        'number_of_rva_and_sizes': c_uint32,
    }.items())
    structs['WindowsCOFFData'] = type('WindowsCOFFData',
                                      base_types,
                                      {'_fields_': fields})

    fields = list({
        'virtual_address': c_uint32,
        'size': c_uint32
    }.items())
    image_data_directory = type('ImageDataDirectory',
                                base_types,
                                {'_fields_': fields})
    structs['ImageDataDirectory'] = image_data_directory

    fields = list({
        'export_table': image_data_directory,
        'import_table': image_data_directory,
        'resource_table': image_data_directory,
        'exception_table': image_data_directory,
        'certificate_table': image_data_directory,
        'base_relocation_table': image_data_directory,
        'debug': image_data_directory,
        'architecture': image_data_directory,
        'global_ptr': image_data_directory,
        'tls_table': image_data_directory,
        'load_config_table': image_data_directory,
        'bound_import': image_data_directory,
        'import_address_table': image_data_directory,
        'delay_import_descriptor': image_data_directory,
        'clr_runtime_header': image_data_directory,
        '_reserved': image_data_directory,
    }.items())

    structs['DataDirectories'] = type('DataDirectories',
                                      base_types,
                                      {'_fields_': fields})

    # TODO: add a __repr_map__ for this to print characteristics
    # in a readable manner
    fields = list({
        'name': c_ubyte*8,
        'virtual_size': c_uint32,
        'virtual_address': c_uint32,
        'size_of_raw_data': c_uint32,
        'pointer_to_raw_data': c_uint32,
        'pointer_to_relocations': c_uint32,
        'pointer_to_line_numbers': c_uint32,
        'number_of_relocations': c_uint16,
        'number_of_line_numbers': c_uint16,
        'characteristics': c_uint32,
    }.items())
    structs['SectionTable'] = type('SectionTable',
                                   base_types,
                                   {'_fields_': fields})

    fields = list({
        'name': c_ubyte*8,
        'value': c_uint32,
        'section_number': c_uint16,
        'type': c_uint16,
        'storage_class': c_uint8,
        'number_of_aux_symbols': c_uint8,
    }.items())
    structs['SymbolTable'] = type('SymbolTable',
                                  base_types,
                                  {'_fields_': fields})

    fields = list({
        'short_name': c_ubyte*8,
        'zeroes': c_uint32,
        'offset': c_uint32,
    }.items())
    structs['SymbolNameRepr'] = type('SymbolNameRepr',
                                     base_types,
                                     {'_fields_': fields})

    fields = list({
        'tag_index': c_uint32,
        'total_size': c_uint32,
        'ptr_to_line_no': c_uint32,
        'ptr_to_next_func': c_uint32,
        '_unused': c_uint16,
    }.items())
    structs['Aux1'] = type('Aux1',
                           base_types,
                           {'_fields_': fields})
    structs['FunctionDefinition'] = structs['Aux1']

    fields = list({
        '_unused1': c_uint32,
        'line_no': c_uint16,
        '_unused2': c_ubyte*6,
        'ptr_to_next_func': c_uint32,
        '_unused3': c_uint16,
    }.items())
    structs['Aux2'] = type('Aux2',
                           base_types,
                           {'_fields_': fields})
    structs['bf_ef_Symbols'] = structs['Aux2']

    fields = list({
        'tag_index': c_uint32,
        'characteristics': c_uint32,
        '_unused': c_ubyte*10,
    }.items())
    structs['Aux3'] = type('Aux3',
                           base_types,
                           {'_fields_': fields})
    structs['WeakExternal'] = structs['Aux3']

    fields = list({
        'file_name': c_ubyte*18,
    }.items())
    structs['Aux4'] = type('Aux4',
                           base_types,
                           {'_fields_': fields})

    structs['Files'] = structs['Aux4']

    fields = list({
        'length': c_uint32,
        'number_of_relocations': c_uint16,
        'number_of_line_numbers': c_uint16,
        'checksum': c_uint32,
        'number': c_uint16,
        'section': c_uint8,
        '_unused': c_ubyte*3,
    }.items())
    structs['Aux5'] = type('Aux5',
                           base_types,
                           {'_fields_': fields})

    structs['SectionDefinition'] = structs['Aux5']

    fields = list({
        'attributes': c_uint32,
        'name': c_uint32,
        'module_handle': c_uint32,
        'delay_import_address_table': c_uint32,
        'delay_import_name_table': c_uint32,
        'bound_delay_import_table': c_uint32,
        'unload_delay_import_table': c_uint32,
        'time_stamp': c_uint32,
    }.items())
    structs['DelayLoadDirectoryTable'] = type('DelayLoadDirectoryTable',
                                              base_types,
                                              {'_fields_': fields})

    # TODO: processor dependent
    fields = list({
        'begin_address': c_uint32,
        'end_address': c_uint32,
        'unwind_info': c_uint32,
    }.items())
    structs['FunctionTableEntry'] = type('FunctionTableEntry',
                                         base_types,
                                         {'_fields_': fields})

    fields = list({
        'page_rva': c_uint32,
        'block_size': c_uint32,
    }.items())
    structs['BaseRelocationBlock'] = type('BaseRelocationBlock',
                                          base_types,
                                          {'_fields_': fields})

    fields = list({
        'type': c_uint16,
        'offset': c_uint16,
    }.items())

    structs['BaseRelocationBlockEntry'] = type('BaseRelocationBlockEntry',
                                               base_types,
                                               {'_fields_': fields,
                                                '__packed__': True})

    fields = list({
        'virtual_address': c_uint32,
        'symbol_table_index': c_uint32,
        'type': c_uint16,
    }.items())
    structs['COFFRelocation'] = type('COFFRelocation',
                                     base_types,
                                     {'_fields_': fields,
                                      '__packed__': True})

    fields = list({
        'characteristics': c_uint32,
        'time_data_stamp': c_uint32,
        'major_version': c_uint16,
        'minor_version': c_uint16,
        'number_of_name_entries': c_uint16,
        'number_of_id_entries': c_uint16,
    }.items())
    structs['ResourceDirectoryTable'] = type('ResourceDirectoryTable',
                                             base_types,
                                             {'_fields_': fields})

    fields = list({
        'integer_id_or_name_offset': c_uint32,
    }.items())
    # TODO: does big endian change the order of these?
    fields.append(('offset', c_uint32, 31))
    fields.append(('data_entry_or_subdirectory', c_uint32, 1))
    rsrc_dir_id_entry = type('ResourceDirectoryEntry',
                             base_types,
                             {'_fields_': fields,
                              '__packed__': True})
    structs['ResourceDirectoryEntry'] = rsrc_dir_id_entry

    # TODO: might be a cleaner way
    fields = list({
        'length': c_uint16,
        'unicode_string': c_ubyte*4,
    }.items())
    structs['ResourceDirectoryString'] = type('ResourceDirectoryString',
                                              base_types,
                                              {'_fields_': fields})

    fields = list({
        'data_rva': c_uint32,
        'size': c_uint32,
        'codepage': c_uint32,
        '_reserved': c_uint32,
    }.items())
    structs['ResourceDataEntry'] = type('ResourceDataEntry',
                                        base_types,
                                        {'_fields_': fields})

    fields = list({
        'sig1': c_uint16,
        'sig2': c_uint16,
        'version': c_uint16,
        'machine': c_uint16,
        'timestamp': c_uint32,
        'size_of_data': c_uint32,
        'ordinal_or_hint': c_uint16,
    }.items())

    # bitfields
    fields.append(('type', c_uint16, 2))
    fields.append(('name_type', c_uint16, 3))
    fields.append(('_reserved', c_uint16, 11))
    structs['ImportHeader'] = type('ImportHeader',
                                   base_types,
                                   {'_fields_': fields,
                                    '__packed__': True})

    fields = list({
        'export_flags': c_uint32,
        'timestamp': c_uint32,
        'major_version': c_uint16,
        'minor_version': c_uint16,
        'name_rva': c_uint32,
        'ordinal_base': c_uint32,
        'address_table_entries': c_uint32,
        'number_of_name_ptrs': c_uint32,
        'export_address_table_rva': c_uint32,
        'name_ptr_rva': c_uint32,
        'ordinal_table_rva': c_uint32,
    }.items())
    structs['ExportDirectoryTable'] = type('ExportDirectoryTable',
                                           base_types,
                                           {'_fields_': fields})

    fields = list({
        'export_rva': c_uint32,
        'forwarder_rva': c_uint32,
    }.items())
    structs['ExportAddressTable'] = type('ExportAddressTable',
                                         base_types,
                                         {'_fields_': fields})

    fields = list({
        'import_lookup_table_rva': c_uint32,
        'timestamp': c_uint32,
        'forwarder_chain': c_uint32,
        'name_rva': c_uint32,
        'import_address_table_rva': c_uint32,
    }.items())
    structs['ImportDirectoryTable'] = type('ImportDirectoryTable',
                                           base_types,
                                           {'_fields_': fields})

    # not making this a proper union to avoid big endian
    # union woes
    fields = [
        ('ordinal_number_or_hint_table_rva', sizet_type,
         (sizeof(sizet_type)*8)-1),
        ('ordinal_or_name_flag', sizet_type, 1),
    ]
    structs['ImportLookupTable'] = type('ImportLookupTable',
                                        base_types,
                                        {'_fields_': fields,
                                         '__packed__': True})

    fields = list({
        'raw_data_start_va': sizet_type,
        'raw_data_end_va': sizet_type,
        'address_of_index': sizet_type,
        'address_of_callbacks': sizet_type,
        'size_of_zero_fill': c_uint32,
        'characteristics': c_uint32,
    }.items())
    structs['TLSDirectory'] = type('TLSDirectory',
                                   base_types,
                                   {'_fields_': fields})

    fields = list({
        'characteristics': c_uint32,
        'timestamp': c_uint32,
        'major_version': c_uint16,
        'minor_version': c_uint16,
        'global_flags_clear': c_uint32,
        'global_flags_set': c_uint32,
        'critical_section_default_timeout': c_uint32,
        'decommit_free_block_threshold': sizet_type,
        'lock_prefix_table': sizet_type,
        'max_allocation_size': sizet_type,
        'virtual_memory_threshold': sizet_type,
        'process_affinity_mask': sizet_type,
        'process_heap_flags': c_uint32,
        'csdversion': c_uint16,
        '_reserved': c_uint16,
        'editlist': sizet_type,
        'securitycookie': sizet_type,
        'sehandler_table': sizet_type,
        'sehandler_count': sizet_type,
        'guard_cf_check_function_pointer': sizet_type,
        'guard_cf_dispatch_function_pointer': sizet_type,
        'guard_cf_function_table': sizet_type,
        'guard_cf_function_count': sizet_type,
        'guard_flags': c_uint32,
        'code_integrity': c_ubyte*12,
        'guard_address_taken_iat_entry_table': sizet_type,
        'guard_address_taken_iat_entry_count': sizet_type,
        'guard_long_jump_target_table': sizet_type,
        'guard_long_jump_target_count': sizet_type,
    }.items())
    structs['LoadConfiguration'] = type('LoadConfiguration',
                                        base_types,
                                        {'_fields_': fields})

    return structs


class PE:
    _MZ_SIG = b'MZ'
    __PE_HDR_PTR_OFF = 0x3c
    __COFF_MAGIC_OFF = 0x18  # magic offset from start of coff header

    def __init__(self, filepath):
        self.filepath = filepath
        with open(filepath, "rb") as f:
            self.contents = bytearray(f.read())

        assert self.contents[:2] == self._MZ_SIG
        self.__dos_header_bytes = self.__get_dos_header_bytes()
        # dep on endianness/arch
        self._endian_pack = '<'
        self._uint16_pack = self._endian_pack + ctypes.c_uint16._type_
        self._uint32_pack = self._endian_pack + ctypes.c_uint32._type_
        self._uint64_pack = self._endian_pack + ctypes.c_uint64._type_

        self._pe_hdr_ptr = unpack_from(self._uint32_pack,
                                       self.contents,
                                       self.__PE_HDR_PTR_OFF)[0]

        dos_stub_off = self.__PE_HDR_PTR_OFF+4
        self.__dos_stub_bytes = self.contents[dos_stub_off:self._pe_hdr_ptr]

        coff_hdr_offset = dos_stub_off + len(self.__dos_stub_bytes)
        coff_magic_offset = coff_hdr_offset + self.__COFF_MAGIC_OFF
        self._magic_number = unpack_from(self._uint16_pack,
                                         self.contents,
                                         coff_magic_offset)[0]
        self._exception_handler_functions = None

        self._rsrc_dir_tabs = []
        self._rsrc_dir_names = []
        self._rsrc_dir_ids = []
        self._rsrc_data_entries = []
        self._rsrc_data = []
        self._import_directory_entries = []
        self._import_lookup_tables = {}
        self.imports = defaultdict(list)
        self._address = 0
        self.sym = {}

        self._fastpath_string_type = c_ubyte*64

        self.__next_offset = coff_hdr_offset

        # the magic number is in an optional headers, so there isn't
        # a guarantee that the value will actually be in the designated
        # location, even in a valid PE file. In that case, default to PE32
        try:
            self._pe_hdr_type = PEHdrType(self._magic_number)
        except ValueError:
            self._pe_hdr_type = PEHdrType.PE32

        additional_bases = (NiceHexFieldRepr,)

        self._structs = create_pe_structures(self._pe_hdr_type,
                                             additional_bases=additional_bases)
        self._sections = {}
        self._parse_pe_header()
        self._parse_resources()
        self._parse_pdata()
        self._parse_imports()

    @property
    def address(self):
        return self._address

    @address.setter
    def address(self, value):
        for k in self.sym.keys():
            self.sym[k] = self.sym[k] - self._address + value
        self._address = value

    def _parse_pe_header(self):
        self.COFFHdr = self._structs['COFFHdr']()
        self._populate_field_from_offset(self.COFFHdr,
                                         self.__next_offset)
        self.__next_offset += sizeof(self.COFFHdr)

        # Start optional headers

        self.StandardCOFFData = self._structs['StandardCOFFData']()
        self._populate_field_from_offset(self.StandardCOFFData,
                                         self.__next_offset)
        self.__next_offset += sizeof(self.StandardCOFFData)

        self.WindowsCOFFData = self._structs['WindowsCOFFData']()
        self._populate_field_from_offset(self.WindowsCOFFData,
                                         self.__next_offset)
        self.__next_offset += sizeof(self.WindowsCOFFData)

        self.DataDirectories = self._structs['DataDirectories']()
        self._populate_field_from_offset(self.DataDirectories,
                                         self.__next_offset)
        self.__next_offset += sizeof(self.DataDirectories)

        sect_tbl_typ = self._structs['SectionTable']*self.COFFHdr.num_sections
        self.SectionTable = sect_tbl_typ()
        self._populate_field_from_offset(self.SectionTable,
                                         self.__next_offset)
        self.__next_offset += sizeof(self.SectionTable)

        # create a section name to section mapping
        self._sections = {bytes(i.name).replace(b'\x00', b'').decode(): i
                          for i in self.SectionTable}

    def _populate_field_from_offset(self, ctype, offset):
        """
        Either write into an existing instance of the type,
        or create a new instance with a cast
        """
        if not hasattr(ctype, '__bases__'):
            # write into an existing instance of the type
            write_into_ctype(ctype, self.contents[offset:])
            return ctype
        return ((ctype*1).from_buffer(self.contents, offset))[0]

    def __get_dos_header_bytes(self):
        return self.contents[2:self.__PE_HDR_PTR_OFF]

    def _parse_resources(self):
        self._rsrc_header = self._sections.get('.rsrc')
        if self._rsrc_header is None:
            return
        self._rsrc_bytes = self._get_section_bytes('.rsrc')
        next_offset = 0
        self.__parse_rsrc_dir_tab_at(next_offset)

    def __parse_rsrc_dir_tab_at(self, offset):
        rsrc_dir_tab_type = self._structs['ResourceDirectoryTable']
        rsrc_dir_tab = rsrc_dir_tab_type()
        next_offset = offset

        write_into_ctype(rsrc_dir_tab, self._rsrc_bytes[next_offset:])
        # self._populate_field_from_offset(rsrc_dir_tab, next_offset)

        self._rsrc_dir_tabs.append(rsrc_dir_tab)
        next_offset += sizeof(rsrc_dir_tab)

        rsrc_dir_entry_type = self._structs['ResourceDirectoryEntry']
        # Name entries
        rsrc_dir_name_entries_type = (rsrc_dir_tab.number_of_name_entries*rsrc_dir_entry_type)
        rsrc_dir_names = rsrc_dir_name_entries_type()

        if sizeof(rsrc_dir_names) != 0:
            write_into_ctype(rsrc_dir_names, self._rsrc_bytes[next_offset:])
            # self._populate_field_from_offset(rsrc_dir_names, next_offset)
            self._rsrc_dir_names.append(rsrc_dir_names)
            next_offset += sizeof(rsrc_dir_names)

        # ID Entries
        rsrc_dir_id_entries_type = (rsrc_dir_tab.number_of_id_entries*rsrc_dir_entry_type)
        rsrc_dir_ids = rsrc_dir_id_entries_type()
        if sizeof(rsrc_dir_ids) != 0:
            write_into_ctype(rsrc_dir_ids, self._rsrc_bytes[next_offset:])
            # self._populate_field_from_offset(rsrc_dir_ids, next_offset)
            self._rsrc_dir_ids.append(rsrc_dir_ids)
            for i in rsrc_dir_ids:
                if i.data_entry_or_subdirectory == 1:
                    self.__parse_rsrc_dir_tab_at(i.offset)
                else:
                    rsrc_data_entry = self._structs['ResourceDataEntry']()
                    write_into_ctype(rsrc_data_entry, self._rsrc_bytes[i.offset:])
                    self._rsrc_data_entries.append(rsrc_data_entry)
                    self._rsrc_data.append(self._get_rsrc_data(rsrc_data_entry))

            next_offset += sizeof(rsrc_dir_ids)

        return next_offset

    def _get_rsrc_data(self, rsrc_data_entry):
        offset = self._virtual_address_to_offset(rsrc_data_entry.data_rva)
        return self.contents[offset:offset+rsrc_data_entry.size]

    def _get_section_bytes(self, section_name):
        header = self._sections.get(section_name)
        if header is None:
            return b''
        bytes_start = header.pointer_to_raw_data
        bytes_end = bytes_start + header.size_of_raw_data
        return self.contents[bytes_start:bytes_end]

    def _get_section_header_by_virtual_address(self, va):
        for i in self.SectionTable:
            if i.virtual_address <= va and va <= i.virtual_address+i.virtual_size:
                return i

    def _get_section_name_by_virtual_address(self, va):
        s = self._get_section_header_by_virtual_address(va)
        if s is None:
            return ''
        return bytes(s.name).replace(b'\x00', b'').decode()

    def _virtual_address_to_offset(self, va):
        section_header = self._get_section_header_by_virtual_address(va)
        offset = (va - section_header.virtual_address)
        return section_header.pointer_to_raw_data + offset

    def _parse_pdata(self):
        pdata_header = self._sections.get('.pdata')
        if pdata_header is None:
            return
        # pdata_bytes = self._get_section_bytes('.pdata')
        function_table_entry_type = self._structs['FunctionTableEntry']
        num_entries = pdata_header.virtual_size // sizeof(function_table_entry_type)
        function_table_type = function_table_entry_type*num_entries
        function_table = function_table_type()
        self._populate_field_from_offset(function_table,
                                         pdata_header.pointer_to_raw_data)
        self._exception_handler_functions = function_table

    def _parse_imports(self):
        import_table_info = self.DataDirectories.import_table
        off = self._virtual_address_to_offset(import_table_info.virtual_address)
        size = import_table_info.size
        import_table_bytes = self.contents[off:off+size]
        self._import_table_bytes = import_table_bytes
        imp_dir_table_type = self._structs['ImportDirectoryTable']
        imp_dir_entries = self._get_non_zero_ctype_entries_from_off(imp_dir_table_type, off)
        self._import_directory_entries.extend(imp_dir_entries)

        # actually get the name of the library for each directory
        for entry in self._import_directory_entries:
            if entry.name_rva == 0:
                continue
            sizet_type = self._structs['size_t']
            libname = self._string_from_va(entry.name_rva)
            import_address_table = self._get_import_lookup_table_at_rva(entry.import_address_table_rva)
            # TODO: might want to copy this as a non-casted type
            self._import_lookup_tables[libname] = import_address_table
            for i, sym in enumerate(import_address_table):
                addr = (i*sizeof(sizet_type)) + entry.import_address_table_rva
                if sym.ordinal_or_name_flag == 1:
                    self.imports[libname].append(sym.ordinal_number_or_hint_table_rva)
                    self.sym[f"imp.{libname}.ord{i}"] = addr
                    continue
                # TODO: maybe parse hint table correctly
                sym_name_string = self._string_from_va(sym.ordinal_number_or_hint_table_rva+2)
                self.imports[libname].append(sym_name_string)
                self.sym[f"imp.{sym_name_string}"] = addr

        # TODO: hint table

    def _string_from_offset(self, offset):
        """
        Fastpath tries to avoid makeing a potentially very
        large bytes object
        """
        try:
            cstring_buffer = self._fastpath_string_type.from_buffer(self.contents, offset)
        except:
            cstring_buffer = create_string_buffer(bytes(self.contents[offset:]))

        cstring = string_at(cstring_buffer)
        return cstring.decode()

    def _string_from_va(self, va):
        offset = self._virtual_address_to_offset(va)
        return self._string_from_offset(offset)

    def _get_non_zero_ctype_entries_from_off(self, ctype, offset):
        """
        get the entries of an array of structs/ctypes that is known
        to end with a zeroed out struct/ctype instance
        """
        # populate_field will rely on this being a ctype type,
        # if it is an instance then the same entry will be populated
        # over and over
        if not hasattr(ctype, '__bases__'):
            ctype = type(ctype)
        table_entries = []
        while True:
            entry = self._populate_field_from_offset(ctype,
                                                     offset)
            offset += sizeof(entry)
            if is_zeroed_ctype(entry):
                break
            table_entries.append(entry)
        return table_entries

    def _get_import_lookup_table_at_rva(self, va):
        import_lookup_tab_typ = self._structs['ImportLookupTable']
        offset = self._virtual_address_to_offset(va)
        table = self._get_non_zero_ctype_entries_from_off(import_lookup_tab_typ,
                                                          offset)
        return table


if __name__ == '__main__':
    pe = PE(os.path.join(os.path.dirname(__file__), "testbins", "ready_unpacked.exe"))
