-- This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild
--
-- This file is compatible with Lua 5.3

local class = require("class")
require("kaitaistruct")
local enum = require("enum")
local stringstream = require("string_stream")
local str_decode = require("string_decode")
local utils = require("utils")

-- 
-- See also: Source (http://www.microsoft.com/whdc/system/platform/firmware/PECOFF.mspx)
MicrosoftPe = class.class(KaitaiStruct)

MicrosoftPe.PeFormat = enum.Enum {
  rom_image = 263,
  pe32 = 267,
  pe32_plus = 523,
}

function MicrosoftPe:_init(io, parent, root)
  KaitaiStruct._init(self, io)
  self._parent = parent
  self._root = root or self
  self:_read()
end

function MicrosoftPe:_read()
  self.mz = MicrosoftPe.MzPlaceholder(self._io, self, self._root)
end

MicrosoftPe.property.pe = {}
function MicrosoftPe.property.pe:get()
  if self._m_pe ~= nil then
    return self._m_pe
  end

  local _pos = self._io:pos()
  self._io:seek(self.mz.ofs_pe)
  self._m_pe = MicrosoftPe.PeHeader(self._io, self, self._root)
  self._io:seek(_pos)
  return self._m_pe
end


-- 
-- See also: Source (https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#the-attribute-certificate-table-image-only)
MicrosoftPe.CertificateEntry = class.class(KaitaiStruct)

MicrosoftPe.CertificateEntry.CertificateRevision = enum.Enum {
  revision_1_0 = 256,
  revision_2_0 = 512,
}

MicrosoftPe.CertificateEntry.CertificateType = enum.Enum {
  x509 = 1,
  pkcs_signed_data = 2,
  reserved_1 = 3,
  ts_stack_signed = 4,
}

function MicrosoftPe.CertificateEntry:_init(io, parent, root)
  KaitaiStruct._init(self, io)
  self._parent = parent
  self._root = root or self
  self:_read()
end

function MicrosoftPe.CertificateEntry:_read()
  self.length = self._io:read_u4le()
  self.revision = MicrosoftPe.CertificateEntry.CertificateRevision(self._io:read_u2le())
  self.certificate_type = MicrosoftPe.CertificateEntry.CertificateType(self._io:read_u2le())
  self.certificate_bytes = self._io:read_bytes((self.length - 8))
end

-- 
-- Specifies the length of the attribute certificate entry.
-- 
-- Contains the certificate version number.
-- 
-- Specifies the type of content in bCertificate.
-- 
-- Contains a certificate, such as an Authenticode signature.

MicrosoftPe.OptionalHeaderWindows = class.class(KaitaiStruct)

MicrosoftPe.OptionalHeaderWindows.SubsystemEnum = enum.Enum {
  unknown = 0,
  native = 1,
  windows_gui = 2,
  windows_cui = 3,
  posix_cui = 7,
  windows_ce_gui = 9,
  efi_application = 10,
  efi_boot_service_driver = 11,
  efi_runtime_driver = 12,
  efi_rom = 13,
  xbox = 14,
  windows_boot_application = 16,
}

function MicrosoftPe.OptionalHeaderWindows:_init(io, parent, root)
  KaitaiStruct._init(self, io)
  self._parent = parent
  self._root = root or self
  self:_read()
end

function MicrosoftPe.OptionalHeaderWindows:_read()
  if self._parent.std.format == MicrosoftPe.PeFormat.pe32 then
    self.image_base_32 = self._io:read_u4le()
  end
  if self._parent.std.format == MicrosoftPe.PeFormat.pe32_plus then
    self.image_base_64 = self._io:read_u8le()
  end
  self.section_alignment = self._io:read_u4le()
  self.file_alignment = self._io:read_u4le()
  self.major_operating_system_version = self._io:read_u2le()
  self.minor_operating_system_version = self._io:read_u2le()
  self.major_image_version = self._io:read_u2le()
  self.minor_image_version = self._io:read_u2le()
  self.major_subsystem_version = self._io:read_u2le()
  self.minor_subsystem_version = self._io:read_u2le()
  self.win32_version_value = self._io:read_u4le()
  self.size_of_image = self._io:read_u4le()
  self.size_of_headers = self._io:read_u4le()
  self.check_sum = self._io:read_u4le()
  self.subsystem = MicrosoftPe.OptionalHeaderWindows.SubsystemEnum(self._io:read_u2le())
  self.dll_characteristics = self._io:read_u2le()
  if self._parent.std.format == MicrosoftPe.PeFormat.pe32 then
    self.size_of_stack_reserve_32 = self._io:read_u4le()
  end
  if self._parent.std.format == MicrosoftPe.PeFormat.pe32_plus then
    self.size_of_stack_reserve_64 = self._io:read_u8le()
  end
  if self._parent.std.format == MicrosoftPe.PeFormat.pe32 then
    self.size_of_stack_commit_32 = self._io:read_u4le()
  end
  if self._parent.std.format == MicrosoftPe.PeFormat.pe32_plus then
    self.size_of_stack_commit_64 = self._io:read_u8le()
  end
  if self._parent.std.format == MicrosoftPe.PeFormat.pe32 then
    self.size_of_heap_reserve_32 = self._io:read_u4le()
  end
  if self._parent.std.format == MicrosoftPe.PeFormat.pe32_plus then
    self.size_of_heap_reserve_64 = self._io:read_u8le()
  end
  if self._parent.std.format == MicrosoftPe.PeFormat.pe32 then
    self.size_of_heap_commit_32 = self._io:read_u4le()
  end
  if self._parent.std.format == MicrosoftPe.PeFormat.pe32_plus then
    self.size_of_heap_commit_64 = self._io:read_u8le()
  end
  self.loader_flags = self._io:read_u4le()
  self.number_of_rva_and_sizes = self._io:read_u4le()
end


MicrosoftPe.OptionalHeaderDataDirs = class.class(KaitaiStruct)

function MicrosoftPe.OptionalHeaderDataDirs:_init(io, parent, root)
  KaitaiStruct._init(self, io)
  self._parent = parent
  self._root = root or self
  self:_read()
end

function MicrosoftPe.OptionalHeaderDataDirs:_read()
  self.export_table = MicrosoftPe.DataDir(self._io, self, self._root)
  self.import_table = MicrosoftPe.DataDir(self._io, self, self._root)
  self.resource_table = MicrosoftPe.DataDir(self._io, self, self._root)
  self.exception_table = MicrosoftPe.DataDir(self._io, self, self._root)
  self.certificate_table = MicrosoftPe.DataDir(self._io, self, self._root)
  self.base_relocation_table = MicrosoftPe.DataDir(self._io, self, self._root)
  self.debug = MicrosoftPe.DataDir(self._io, self, self._root)
  self.architecture = MicrosoftPe.DataDir(self._io, self, self._root)
  self.global_ptr = MicrosoftPe.DataDir(self._io, self, self._root)
  self.tls_table = MicrosoftPe.DataDir(self._io, self, self._root)
  self.load_config_table = MicrosoftPe.DataDir(self._io, self, self._root)
  self.bound_import = MicrosoftPe.DataDir(self._io, self, self._root)
  self.iat = MicrosoftPe.DataDir(self._io, self, self._root)
  self.delay_import_descriptor = MicrosoftPe.DataDir(self._io, self, self._root)
  self.clr_runtime_header = MicrosoftPe.DataDir(self._io, self, self._root)
end


MicrosoftPe.DataDir = class.class(KaitaiStruct)

function MicrosoftPe.DataDir:_init(io, parent, root)
  KaitaiStruct._init(self, io)
  self._parent = parent
  self._root = root or self
  self:_read()
end

function MicrosoftPe.DataDir:_read()
  self.virtual_address = self._io:read_u4le()
  self.size = self._io:read_u4le()
end


MicrosoftPe.CoffSymbol = class.class(KaitaiStruct)

function MicrosoftPe.CoffSymbol:_init(io, parent, root)
  KaitaiStruct._init(self, io)
  self._parent = parent
  self._root = root or self
  self:_read()
end

function MicrosoftPe.CoffSymbol:_read()
  self._raw_name_annoying = self._io:read_bytes(8)
  local _io = KaitaiStream(stringstream(self._raw_name_annoying))
  self.name_annoying = MicrosoftPe.Annoyingstring(_io, self, self._root)
  self.value = self._io:read_u4le()
  self.section_number = self._io:read_u2le()
  self.type = self._io:read_u2le()
  self.storage_class = self._io:read_u1()
  self.number_of_aux_symbols = self._io:read_u1()
end

MicrosoftPe.CoffSymbol.property.section = {}
function MicrosoftPe.CoffSymbol.property.section:get()
  if self._m_section ~= nil then
    return self._m_section
  end

  self._m_section = self._root.pe.sections[(self.section_number - 1) + 1]
  return self._m_section
end

MicrosoftPe.CoffSymbol.property.data = {}
function MicrosoftPe.CoffSymbol.property.data:get()
  if self._m_data ~= nil then
    return self._m_data
  end

  local _pos = self._io:pos()
  self._io:seek((self.section.pointer_to_raw_data + self.value))
  self._m_data = self._io:read_bytes(1)
  self._io:seek(_pos)
  return self._m_data
end


MicrosoftPe.PeHeader = class.class(KaitaiStruct)

function MicrosoftPe.PeHeader:_init(io, parent, root)
  KaitaiStruct._init(self, io)
  self._parent = parent
  self._root = root or self
  self:_read()
end

function MicrosoftPe.PeHeader:_read()
  self.pe_signature = self._io:read_bytes(4)
  if not(self.pe_signature == "\080\069\000\000") then
    error("not equal, expected " ..  "\080\069\000\000" .. ", but got " .. self.pe_signature)
  end
  self.coff_hdr = MicrosoftPe.CoffHeader(self._io, self, self._root)
  self._raw_optional_hdr = self._io:read_bytes(self.coff_hdr.size_of_optional_header)
  local _io = KaitaiStream(stringstream(self._raw_optional_hdr))
  self.optional_hdr = MicrosoftPe.OptionalHeader(_io, self, self._root)
  self.sections = {}
  for i = 0, self.coff_hdr.number_of_sections - 1 do
    self.sections[i + 1] = MicrosoftPe.Section(self._io, self, self._root)
  end
end

MicrosoftPe.PeHeader.property.certificate_table = {}
function MicrosoftPe.PeHeader.property.certificate_table:get()
  if self._m_certificate_table ~= nil then
    return self._m_certificate_table
  end

  if self.optional_hdr.data_dirs.certificate_table.virtual_address ~= 0 then
    local _pos = self._io:pos()
    self._io:seek(self.optional_hdr.data_dirs.certificate_table.virtual_address)
    self._raw__m_certificate_table = self._io:read_bytes(self.optional_hdr.data_dirs.certificate_table.size)
    local _io = KaitaiStream(stringstream(self._raw__m_certificate_table))
    self._m_certificate_table = MicrosoftPe.CertificateTable(_io, self, self._root)
    self._io:seek(_pos)
  end
  return self._m_certificate_table
end


MicrosoftPe.OptionalHeader = class.class(KaitaiStruct)

function MicrosoftPe.OptionalHeader:_init(io, parent, root)
  KaitaiStruct._init(self, io)
  self._parent = parent
  self._root = root or self
  self:_read()
end

function MicrosoftPe.OptionalHeader:_read()
  self.std = MicrosoftPe.OptionalHeaderStd(self._io, self, self._root)
  self.windows = MicrosoftPe.OptionalHeaderWindows(self._io, self, self._root)
  self.data_dirs = MicrosoftPe.OptionalHeaderDataDirs(self._io, self, self._root)
end


MicrosoftPe.Section = class.class(KaitaiStruct)

function MicrosoftPe.Section:_init(io, parent, root)
  KaitaiStruct._init(self, io)
  self._parent = parent
  self._root = root or self
  self:_read()
end

function MicrosoftPe.Section:_read()
  self.name = str_decode.decode(KaitaiStream.bytes_strip_right(self._io:read_bytes(8), 0), "UTF-8")
  self.virtual_size = self._io:read_u4le()
  self.virtual_address = self._io:read_u4le()
  self.size_of_raw_data = self._io:read_u4le()
  self.pointer_to_raw_data = self._io:read_u4le()
  self.pointer_to_relocations = self._io:read_u4le()
  self.pointer_to_linenumbers = self._io:read_u4le()
  self.number_of_relocations = self._io:read_u2le()
  self.number_of_linenumbers = self._io:read_u2le()
  self.characteristics = self._io:read_u4le()
end

MicrosoftPe.Section.property.body = {}
function MicrosoftPe.Section.property.body:get()
  if self._m_body ~= nil then
    return self._m_body
  end

  local _pos = self._io:pos()
  self._io:seek(self.pointer_to_raw_data)
  self._m_body = self._io:read_bytes(self.size_of_raw_data)
  self._io:seek(_pos)
  return self._m_body
end


MicrosoftPe.CertificateTable = class.class(KaitaiStruct)

function MicrosoftPe.CertificateTable:_init(io, parent, root)
  KaitaiStruct._init(self, io)
  self._parent = parent
  self._root = root or self
  self:_read()
end

function MicrosoftPe.CertificateTable:_read()
  self.items = {}
  local i = 0
  while not self._io:is_eof() do
    self.items[i + 1] = MicrosoftPe.CertificateEntry(self._io, self, self._root)
    i = i + 1
  end
end


MicrosoftPe.MzPlaceholder = class.class(KaitaiStruct)

function MicrosoftPe.MzPlaceholder:_init(io, parent, root)
  KaitaiStruct._init(self, io)
  self._parent = parent
  self._root = root or self
  self:_read()
end

function MicrosoftPe.MzPlaceholder:_read()
  self.magic = self._io:read_bytes(2)
  if not(self.magic == "\077\090") then
    error("not equal, expected " ..  "\077\090" .. ", but got " .. self.magic)
  end
  self.data1 = self._io:read_bytes(58)
  self.ofs_pe = self._io:read_u4le()
end

-- 
-- In PE file, an offset to PE header.

MicrosoftPe.OptionalHeaderStd = class.class(KaitaiStruct)

function MicrosoftPe.OptionalHeaderStd:_init(io, parent, root)
  KaitaiStruct._init(self, io)
  self._parent = parent
  self._root = root or self
  self:_read()
end

function MicrosoftPe.OptionalHeaderStd:_read()
  self.format = MicrosoftPe.PeFormat(self._io:read_u2le())
  self.major_linker_version = self._io:read_u1()
  self.minor_linker_version = self._io:read_u1()
  self.size_of_code = self._io:read_u4le()
  self.size_of_initialized_data = self._io:read_u4le()
  self.size_of_uninitialized_data = self._io:read_u4le()
  self.address_of_entry_point = self._io:read_u4le()
  self.base_of_code = self._io:read_u4le()
  if self.format == MicrosoftPe.PeFormat.pe32 then
    self.base_of_data = self._io:read_u4le()
  end
end


-- 
-- See also: 3.3. COFF File Header (Object and Image)
MicrosoftPe.CoffHeader = class.class(KaitaiStruct)

MicrosoftPe.CoffHeader.MachineType = enum.Enum {
  unknown = 0,
  i386 = 332,
  r4000 = 358,
  wcemipsv2 = 361,
  alpha = 388,
  sh3 = 418,
  sh3dsp = 419,
  sh4 = 422,
  sh5 = 424,
  arm = 448,
  thumb = 450,
  armnt = 452,
  am33 = 467,
  powerpc = 496,
  powerpcfp = 497,
  ia64 = 512,
  mips16 = 614,
  mipsfpu = 870,
  mipsfpu16 = 1126,
  ebc = 3772,
  riscv32 = 20530,
  riscv64 = 20580,
  riscv128 = 20776,
  amd64 = 34404,
  m32r = 36929,
  arm64 = 43620,
}

function MicrosoftPe.CoffHeader:_init(io, parent, root)
  KaitaiStruct._init(self, io)
  self._parent = parent
  self._root = root or self
  self:_read()
end

function MicrosoftPe.CoffHeader:_read()
  self.machine = MicrosoftPe.CoffHeader.MachineType(self._io:read_u2le())
  self.number_of_sections = self._io:read_u2le()
  self.time_date_stamp = self._io:read_u4le()
  self.pointer_to_symbol_table = self._io:read_u4le()
  self.number_of_symbols = self._io:read_u4le()
  self.size_of_optional_header = self._io:read_u2le()
  self.characteristics = self._io:read_u2le()
end

MicrosoftPe.CoffHeader.property.symbol_table_size = {}
function MicrosoftPe.CoffHeader.property.symbol_table_size:get()
  if self._m_symbol_table_size ~= nil then
    return self._m_symbol_table_size
  end

  self._m_symbol_table_size = (self.number_of_symbols * 18)
  return self._m_symbol_table_size
end

MicrosoftPe.CoffHeader.property.symbol_name_table_offset = {}
function MicrosoftPe.CoffHeader.property.symbol_name_table_offset:get()
  if self._m_symbol_name_table_offset ~= nil then
    return self._m_symbol_name_table_offset
  end

  self._m_symbol_name_table_offset = (self.pointer_to_symbol_table + self.symbol_table_size)
  return self._m_symbol_name_table_offset
end

MicrosoftPe.CoffHeader.property.symbol_name_table_size = {}
function MicrosoftPe.CoffHeader.property.symbol_name_table_size:get()
  if self._m_symbol_name_table_size ~= nil then
    return self._m_symbol_name_table_size
  end

  local _pos = self._io:pos()
  self._io:seek(self.symbol_name_table_offset)
  self._m_symbol_name_table_size = self._io:read_u4le()
  self._io:seek(_pos)
  return self._m_symbol_name_table_size
end

MicrosoftPe.CoffHeader.property.symbol_table = {}
function MicrosoftPe.CoffHeader.property.symbol_table:get()
  if self._m_symbol_table ~= nil then
    return self._m_symbol_table
  end

  local _pos = self._io:pos()
  self._io:seek(self.pointer_to_symbol_table)
  self._m_symbol_table = {}
  for i = 0, self.number_of_symbols - 1 do
    self._m_symbol_table[i + 1] = MicrosoftPe.CoffSymbol(self._io, self, self._root)
  end
  self._io:seek(_pos)
  return self._m_symbol_table
end


MicrosoftPe.Annoyingstring = class.class(KaitaiStruct)

function MicrosoftPe.Annoyingstring:_init(io, parent, root)
  KaitaiStruct._init(self, io)
  self._parent = parent
  self._root = root or self
  self:_read()
end

function MicrosoftPe.Annoyingstring:_read()
end

MicrosoftPe.Annoyingstring.property.name_from_offset = {}
function MicrosoftPe.Annoyingstring.property.name_from_offset:get()
  if self._m_name_from_offset ~= nil then
    return self._m_name_from_offset
  end

  if self.name_zeroes == 0 then
    local _io = self._root._io
    local _pos = _io:pos()
    _io:seek(utils.box_unwrap((self.name_zeroes == 0) and utils.box_wrap((self._parent._parent.symbol_name_table_offset + self.name_offset)) or (0)))
    self._m_name_from_offset = str_decode.decode(_io:read_bytes_term(0, false, true, false), "ascii")
    _io:seek(_pos)
  end
  return self._m_name_from_offset
end

MicrosoftPe.Annoyingstring.property.name_offset = {}
function MicrosoftPe.Annoyingstring.property.name_offset:get()
  if self._m_name_offset ~= nil then
    return self._m_name_offset
  end

  local _pos = self._io:pos()
  self._io:seek(4)
  self._m_name_offset = self._io:read_u4le()
  self._io:seek(_pos)
  return self._m_name_offset
end

MicrosoftPe.Annoyingstring.property.name = {}
function MicrosoftPe.Annoyingstring.property.name:get()
  if self._m_name ~= nil then
    return self._m_name
  end

  self._m_name = utils.box_unwrap((self.name_zeroes == 0) and utils.box_wrap(self.name_from_offset) or (self.name_from_short))
  return self._m_name
end

MicrosoftPe.Annoyingstring.property.name_zeroes = {}
function MicrosoftPe.Annoyingstring.property.name_zeroes:get()
  if self._m_name_zeroes ~= nil then
    return self._m_name_zeroes
  end

  local _pos = self._io:pos()
  self._io:seek(0)
  self._m_name_zeroes = self._io:read_u4le()
  self._io:seek(_pos)
  return self._m_name_zeroes
end

MicrosoftPe.Annoyingstring.property.name_from_short = {}
function MicrosoftPe.Annoyingstring.property.name_from_short:get()
  if self._m_name_from_short ~= nil then
    return self._m_name_from_short
  end

  if self.name_zeroes ~= 0 then
    local _pos = self._io:pos()
    self._io:seek(0)
    self._m_name_from_short = str_decode.decode(self._io:read_bytes_term(0, false, true, false), "ascii")
    self._io:seek(_pos)
  end
  return self._m_name_from_short
end


