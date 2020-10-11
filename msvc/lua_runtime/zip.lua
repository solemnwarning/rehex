-- This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild
--
-- This file is compatible with Lua 5.3

local class = require("class")
require("kaitaistruct")
local enum = require("enum")
local stringstream = require("string_stream")
local str_decode = require("string_decode")

-- 
-- ZIP is a popular archive file format, introduced in 1989 by Phil Katz
-- and originally implemented in PKZIP utility by PKWARE.
-- 
-- Thanks to solid support of it in most desktop environments and
-- operating systems, and algorithms / specs availability in public
-- domain, it quickly became tool of choice for implementing file
-- containers.
-- 
-- For example, Java .jar files, OpenDocument, Office Open XML, EPUB files
-- are actually ZIP archives.
-- See also: Source (https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
Zip = class.class(KaitaiStruct)

Zip.Compression = enum.Enum {
  none = 0,
  shrunk = 1,
  reduced_1 = 2,
  reduced_2 = 3,
  reduced_3 = 4,
  reduced_4 = 5,
  imploded = 6,
  deflated = 8,
  enhanced_deflated = 9,
  pkware_dcl_imploded = 10,
  bzip2 = 12,
  lzma = 14,
  ibm_terse = 18,
  ibm_lz77_z = 19,
  ppmd = 98,
}

Zip.ExtraCodes = enum.Enum {
  zip64 = 1,
  av_info = 7,
  os2 = 9,
  ntfs = 10,
  openvms = 12,
  pkware_unix = 13,
  file_stream_and_fork_descriptors = 14,
  patch_descriptor = 15,
  pkcs7 = 20,
  x509_cert_id_and_signature_for_file = 21,
  x509_cert_id_for_central_dir = 22,
  strong_encryption_header = 23,
  record_management_controls = 24,
  pkcs7_enc_recip_cert_list = 25,
  ibm_s390_uncomp = 101,
  ibm_s390_comp = 102,
  poszip_4690 = 18064,
  extended_timestamp = 21589,
  infozip_unix = 30805,
  infozip_unix_var_size = 30837,
}

function Zip:_init(io, parent, root)
  KaitaiStruct._init(self, io)
  self._parent = parent
  self._root = root or self
  self:_read()
end

function Zip:_read()
  self.sections = {}
  local i = 1
  while not self._io:is_eof() do
    self.sections[i] = Zip.PkSection(self._io, self, self._root)
    i = i + 1
  end
end


Zip.LocalFile = class.class(KaitaiStruct)

function Zip.LocalFile:_init(io, parent, root)
  KaitaiStruct._init(self, io)
  self._parent = parent
  self._root = root or self
  self:_read()
end

function Zip.LocalFile:_read()
  self.header = Zip.LocalFileHeader(self._io, self, self._root)
  self.body = self._io:read_bytes(self.header.len_body_compressed)
end


Zip.DataDescriptor = class.class(KaitaiStruct)

function Zip.DataDescriptor:_init(io, parent, root)
  KaitaiStruct._init(self, io)
  self._parent = parent
  self._root = root or self
  self:_read()
end

function Zip.DataDescriptor:_read()
  self.crc32 = self._io:read_u4le()
  self.len_body_compressed = self._io:read_u4le()
  self.len_body_uncompressed = self._io:read_u4le()
end


Zip.ExtraField = class.class(KaitaiStruct)

function Zip.ExtraField:_init(io, parent, root)
  KaitaiStruct._init(self, io)
  self._parent = parent
  self._root = root or self
  self:_read()
end

function Zip.ExtraField:_read()
  self.code = Zip.ExtraCodes(self._io:read_u2le())
  self.len_body = self._io:read_u2le()
  local _on = self.code
  if _on == Zip.ExtraCodes.ntfs then
    self._raw_body = self._io:read_bytes(self.len_body)
    local _io = KaitaiStream(stringstream(self._raw_body))
    self.body = Zip.ExtraField.Ntfs(_io, self, self._root)
  elseif _on == Zip.ExtraCodes.extended_timestamp then
    self._raw_body = self._io:read_bytes(self.len_body)
    local _io = KaitaiStream(stringstream(self._raw_body))
    self.body = Zip.ExtraField.ExtendedTimestamp(_io, self, self._root)
  elseif _on == Zip.ExtraCodes.infozip_unix_var_size then
    self._raw_body = self._io:read_bytes(self.len_body)
    local _io = KaitaiStream(stringstream(self._raw_body))
    self.body = Zip.ExtraField.InfozipUnixVarSize(_io, self, self._root)
  else
    self.body = self._io:read_bytes(self.len_body)
  end
end


-- 
-- See also: Source (https://github.com/LuaDist/zip/blob/master/proginfo/extrafld.txt#L191)
Zip.ExtraField.Ntfs = class.class(KaitaiStruct)

function Zip.ExtraField.Ntfs:_init(io, parent, root)
  KaitaiStruct._init(self, io)
  self._parent = parent
  self._root = root or self
  self:_read()
end

function Zip.ExtraField.Ntfs:_read()
  self.reserved = self._io:read_u4le()
  self.attributes = {}
  local i = 1
  while not self._io:is_eof() do
    self.attributes[i] = Zip.ExtraField.Ntfs.Attribute(self._io, self, self._root)
    i = i + 1
  end
end


Zip.ExtraField.Ntfs.Attribute = class.class(KaitaiStruct)

function Zip.ExtraField.Ntfs.Attribute:_init(io, parent, root)
  KaitaiStruct._init(self, io)
  self._parent = parent
  self._root = root or self
  self:_read()
end

function Zip.ExtraField.Ntfs.Attribute:_read()
  self.tag = self._io:read_u2le()
  self.len_body = self._io:read_u2le()
  local _on = self.tag
  if _on == 1 then
    self._raw_body = self._io:read_bytes(self.len_body)
    local _io = KaitaiStream(stringstream(self._raw_body))
    self.body = Zip.ExtraField.Ntfs.Attribute1(_io, self, self._root)
  else
    self.body = self._io:read_bytes(self.len_body)
  end
end


Zip.ExtraField.Ntfs.Attribute1 = class.class(KaitaiStruct)

function Zip.ExtraField.Ntfs.Attribute1:_init(io, parent, root)
  KaitaiStruct._init(self, io)
  self._parent = parent
  self._root = root or self
  self:_read()
end

function Zip.ExtraField.Ntfs.Attribute1:_read()
  self.last_mod_time = self._io:read_u8le()
  self.last_access_time = self._io:read_u8le()
  self.creation_time = self._io:read_u8le()
end


-- 
-- See also: Source (https://github.com/LuaDist/zip/blob/master/proginfo/extrafld.txt#L817)
Zip.ExtraField.ExtendedTimestamp = class.class(KaitaiStruct)

function Zip.ExtraField.ExtendedTimestamp:_init(io, parent, root)
  KaitaiStruct._init(self, io)
  self._parent = parent
  self._root = root or self
  self:_read()
end

function Zip.ExtraField.ExtendedTimestamp:_read()
  self.flags = self._io:read_u1()
  self.mod_time = self._io:read_u4le()
  if not(self._io:is_eof()) then
    self.access_time = self._io:read_u4le()
  end
  if not(self._io:is_eof()) then
    self.create_time = self._io:read_u4le()
  end
end


-- 
-- See also: Source (https://github.com/LuaDist/zip/blob/master/proginfo/extrafld.txt#L1339)
Zip.ExtraField.InfozipUnixVarSize = class.class(KaitaiStruct)

function Zip.ExtraField.InfozipUnixVarSize:_init(io, parent, root)
  KaitaiStruct._init(self, io)
  self._parent = parent
  self._root = root or self
  self:_read()
end

function Zip.ExtraField.InfozipUnixVarSize:_read()
  self.version = self._io:read_u1()
  self.len_uid = self._io:read_u1()
  self.uid = self._io:read_bytes(self.len_uid)
  self.len_gid = self._io:read_u1()
  self.gid = self._io:read_bytes(self.len_gid)
end

-- 
-- Version of this extra field, currently 1.
-- 
-- Size of UID field.
-- 
-- UID (User ID) for a file.
-- 
-- Size of GID field.
-- 
-- GID (Group ID) for a file.

-- 
-- See also: - 4.3.12 (https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
Zip.CentralDirEntry = class.class(KaitaiStruct)

function Zip.CentralDirEntry:_init(io, parent, root)
  KaitaiStruct._init(self, io)
  self._parent = parent
  self._root = root or self
  self:_read()
end

function Zip.CentralDirEntry:_read()
  self.version_made_by = self._io:read_u2le()
  self.version_needed_to_extract = self._io:read_u2le()
  self.flags = self._io:read_u2le()
  self.compression_method = Zip.Compression(self._io:read_u2le())
  self.last_mod_file_time = self._io:read_u2le()
  self.last_mod_file_date = self._io:read_u2le()
  self.crc32 = self._io:read_u4le()
  self.len_body_compressed = self._io:read_u4le()
  self.len_body_uncompressed = self._io:read_u4le()
  self.len_file_name = self._io:read_u2le()
  self.len_extra = self._io:read_u2le()
  self.len_comment = self._io:read_u2le()
  self.disk_number_start = self._io:read_u2le()
  self.int_file_attr = self._io:read_u2le()
  self.ext_file_attr = self._io:read_u4le()
  self.ofs_local_header = self._io:read_s4le()
  self.file_name = str_decode.decode(self._io:read_bytes(self.len_file_name), "UTF-8")
  self._raw_extra = self._io:read_bytes(self.len_extra)
  local _io = KaitaiStream(stringstream(self._raw_extra))
  self.extra = Zip.Extras(_io, self, self._root)
  self.comment = str_decode.decode(self._io:read_bytes(self.len_comment), "UTF-8")
end

Zip.CentralDirEntry.property.local_header = {}
function Zip.CentralDirEntry.property.local_header:get()
  if self._m_local_header ~= nil then
    return self._m_local_header
  end

  local _pos = self._io:pos()
  self._io:seek(self.ofs_local_header)
  self._m_local_header = Zip.PkSection(self._io, self, self._root)
  self._io:seek(_pos)
  return self._m_local_header
end


Zip.PkSection = class.class(KaitaiStruct)

function Zip.PkSection:_init(io, parent, root)
  KaitaiStruct._init(self, io)
  self._parent = parent
  self._root = root or self
  self:_read()
end

function Zip.PkSection:_read()
  self.magic = self._io:ensure_fixed_contents("\080\075")
  self.section_type = self._io:read_u2le()
  local _on = self.section_type
  if _on == 513 then
    self.body = Zip.CentralDirEntry(self._io, self, self._root)
  elseif _on == 1027 then
    self.body = Zip.LocalFile(self._io, self, self._root)
  elseif _on == 1541 then
    self.body = Zip.EndOfCentralDir(self._io, self, self._root)
  elseif _on == 2055 then
    self.body = Zip.DataDescriptor(self._io, self, self._root)
  end
end


Zip.Extras = class.class(KaitaiStruct)

function Zip.Extras:_init(io, parent, root)
  KaitaiStruct._init(self, io)
  self._parent = parent
  self._root = root or self
  self:_read()
end

function Zip.Extras:_read()
  self.entries = {}
  local i = 1
  while not self._io:is_eof() do
    self.entries[i] = Zip.ExtraField(self._io, self, self._root)
    i = i + 1
  end
end


Zip.LocalFileHeader = class.class(KaitaiStruct)

function Zip.LocalFileHeader:_init(io, parent, root)
  KaitaiStruct._init(self, io)
  self._parent = parent
  self._root = root or self
  self:_read()
end

function Zip.LocalFileHeader:_read()
  self.version = self._io:read_u2le()
  self.flags = self._io:read_u2le()
  self.compression_method = Zip.Compression(self._io:read_u2le())
  self.file_mod_time = self._io:read_u2le()
  self.file_mod_date = self._io:read_u2le()
  self.crc32 = self._io:read_u4le()
  self.len_body_compressed = self._io:read_u4le()
  self.len_body_uncompressed = self._io:read_u4le()
  self.len_file_name = self._io:read_u2le()
  self.len_extra = self._io:read_u2le()
  self.file_name = str_decode.decode(self._io:read_bytes(self.len_file_name), "UTF-8")
  self._raw_extra = self._io:read_bytes(self.len_extra)
  local _io = KaitaiStream(stringstream(self._raw_extra))
  self.extra = Zip.Extras(_io, self, self._root)
end


Zip.EndOfCentralDir = class.class(KaitaiStruct)

function Zip.EndOfCentralDir:_init(io, parent, root)
  KaitaiStruct._init(self, io)
  self._parent = parent
  self._root = root or self
  self:_read()
end

function Zip.EndOfCentralDir:_read()
  self.disk_of_end_of_central_dir = self._io:read_u2le()
  self.disk_of_central_dir = self._io:read_u2le()
  self.num_central_dir_entries_on_disk = self._io:read_u2le()
  self.num_central_dir_entries_total = self._io:read_u2le()
  self.len_central_dir = self._io:read_u4le()
  self.ofs_central_dir = self._io:read_u4le()
  self.len_comment = self._io:read_u2le()
  self.comment = str_decode.decode(self._io:read_bytes(self.len_comment), "UTF-8")
end


