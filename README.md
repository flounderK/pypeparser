# peparser
A Windows Portable Executable (PE) parser written in python.

Compatibility is guaranteed to be bad (especially for non-native endian PE files)


## Human Readable Repr
```
In [3]: print(pe.COFFHdr)

signature: b'PE\x00\x00'
machine: IMAGE_FILE_MACHINE_I386: 0x14c
num_sections: 0x2
timedatestamp: 2015-06-03 04:52:41
sym_tab_ptr: 0x0
sym_tab_no: 0x0
opt_hdr_sz: 0xe0
characteristics: IMAGE_FILE_DLL|IMAGE_FILE_32BIT_MACHINE|IMAGE_FILE_EXECUTABLE_IMAGE: 0x2102
```

```
In [4]: bytes(pe.COFFHdr)
Out[4]: b'PE\x00\x00L\x01\x02\x00Y\xc0nU\x00\x00\x00\x00\x00\x00\x00\x00\xe0\x00\x02!'
```

```
In [5]: print(pe.WindowsCOFFData)

imagebase: 0x10000000
section_alignment: 0x1000
file_alignment: 0x200
major_os_version: 0xa
minor_os_version: 0x0
major_image_version: 0xa
minor_image_version: 0x0
major_subsystem_version: 0xa
minor_subsystem_version: 0x0
win32_version_value: 0x0
image_sz: 0x4000
headers_sz: 0x400
checksum: 0x77b2
subsystem: IMAGE_SUBSYSTEM_WINDOWS_GUI|IMAGE_SUBSYSTEM_NATIVE: 0x3
dll_characteristics: IMAGE_DLLCHARACTERISTICS_NO_SEH|IMAGE_DLLCHARACTERISTICS_NX_COMPAT|IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE: 0x540
stack_reserve_sz: 0x40000
stack_commit_sz: 0x1000
heap_reserve_sz: 0x100000
heap_commit_sz: 0x1000
loader_flags: 0x0
number_of_rva_and_sizes: 0x10
```
