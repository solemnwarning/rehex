#ifndef ELF_H
#define ELF_H

enum <unsigned char> ELF_Class
{
	ELF_CLASS_32BIT = 1,
	ELF_CLASS_64BIT
};

enum <unsigned char> ELF_Endianness
{
	ELF_LITTLE_ENDIAN = 1,
	ELF_BIG_ENDIAN
};

enum <uint16_t> ELF_Type
{
	ET_NONE = 0,
	ET_REL,
	ET_EXEC,
	ET_DYN,
	ET_CORE
};

struct ELF_FileHeader
{
	unsigned char e_ident_magic[4];
	enum ELF_Class e_ident_class;
	enum ELF_Endianness e_ident_endian;
	unsigned char e_ident_version;
	unsigned char e_ident_osabi;
	unsigned char e_ident_abiversion;
	unsigned char e_ident_pad[7];
	
	switch(e_ident_endian)
	{
		case ELF_LITTLE_ENDIAN:
			LittleEndian();
			break;
			
		case ELF_BIG_ENDIAN:
			BigEndian();
			break;
			
		default:
			Error("Unexpected e_ident[EI_DATA] value");
	}
	
	enum ELF_Type e_type;
	uint16_t e_machine;
	uint32_t e_version;
	
	switch(e_ident_class)
	{
		case ELF_CLASS_32BIT:
			uint32_t e_entry;
			uint32_t e_phoff;
			uint32_t e_shoff;
			break;
			
		case ELF_CLASS_64BIT:
			uint64_t e_entry;
			uint64_t e_phoff;
			uint64_t e_shoff;
			break;
		
		default:
			Error("Unexpected e_ident[EI_CLASS] value");
	}
	
	uint32_t e_flags;
	uint16_t e_ehsize;
	uint16_t e_phentsize;
	uint16_t e_phnum;
	uint16_t e_shentsize;
	uint16_t e_shnum;
	uint16_t e_shstrndx;
};

struct ELF_ProgramHeaderEntry(enum ELF_Class ei_class)
{
	uint32_t p_type;
	
	if(ei_class == ELF_CLASS_32BIT)
	{
		uint32_t p_offset;
		uint32_t p_vaddr;
		uint32_t p_paddr;
		uint32_t p_filesz;
		uint32_t p_memsz;
		uint32_t p_flags;
		uint32_t p_align;
	}
	else if(ei_class == ELF_CLASS_64BIT)
	{
		uint32_t p_flags;
		uint64_t p_offset;
		uint64_t p_vaddr;
		uint64_t p_paddr;
		uint64_t p_filesz;
		uint64_t p_memsz;
		uint64_t p_align;
	}
};

enum <uint32_t> ELF_SectionHeaderType
{
	SHT_NULL = 0x0,
	SHT_PROGBITS,
	SHT_SYMTAB,
	SHT_STRTAB,
	SHT_RELA,
	SHT_HASH,
	SHT_DYNAMIC,
	SHT_NOTE,
	SHT_NOBITS,
	SHT_REL,
	SHT_SHLIB,
	SHT_DYNSYM,
	SHT_INIT_ARRAY = 0xE,
	SHT_FINI_ARRAY,
	SHT_PREINIT_ARRAY,
	SHT_GROUP,
	SHT_SYMTAB_SHNDX,
	SHT_NUM
};

struct ELF_SectionHeaderEntry(enum ELF_Class ei_class)
{
	uint32_t sh_name;
	enum ELF_SectionHeaderType sh_type;
	
	if(ei_class == ELF_CLASS_32BIT)
	{
		uint32_t sh_flags;
		uint32_t sh_addr;
		uint32_t sh_offset;
		uint32_t sh_size;
		uint32_t sh_link;
		uint32_t sh_info;
		uint32_t sh_addralign;
		uint32_t sh_entsize;
	}
	else if(ei_class == ELF_CLASS_64BIT)
	{
		uint64_t sh_flags;
		uint64_t sh_addr;
		uint64_t sh_offset;
		uint64_t sh_size;
		uint32_t sh_link;
		uint32_t sh_info;
		uint64_t sh_addralign;
		uint64_t sh_entsize;
	}
};

#endif /* !ELF_H */
