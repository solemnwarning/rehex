#ifndef DWARF_V1_H
#define DWARF_V1_H

#include "elf.h"

enum <uint16_t> DwarfV1_Tag
{
	DwarfV1_TAG_padding = 0x0000,
	DwarfV1_TAG_array_type = 0x0001,
	DwarfV1_TAG_class_type = 0x0002,
	DwarfV1_TAG_entry_point = 0x0003,
	DwarfV1_TAG_enumeration_type = 0x0004,
	DwarfV1_TAG_formal_parameter = 0x0005,
	DwarfV1_TAG_global_subroutine = 0x0006,
	DwarfV1_TAG_global_variable = 0x0007,
	DwarfV1_TAG_label = 0x000a,
	DwarfV1_TAG_lexical_block = 0x000b,
	DwarfV1_TAG_local_variable = 0x000c,
	DwarfV1_TAG_member = 0x000d,
	DwarfV1_TAG_pointer_type = 0x000f,
	DwarfV1_TAG_reference_type = 0x0010,
	DwarfV1_TAG_compile_unit = 0x0011,
	DwarfV1_TAG_source_file = 0x0011,
	DwarfV1_TAG_string_type = 0x0012,
	DwarfV1_TAG_structure_type = 0x0013,
	DwarfV1_TAG_subroutine = 0x0014,
	DwarfV1_TAG_subroutine_type = 0x0015,
	DwarfV1_TAG_typedef = 0x0016,
	DwarfV1_TAG_union_type = 0x0017,
	DwarfV1_TAG_unspecified_parameters = 0x0018,
	DwarfV1_TAG_variant = 0x0019,
	DwarfV1_TAG_common_block = 0x001a,
	DwarfV1_TAG_common_inclusion = 0x001b,
	DwarfV1_TAG_inheritance = 0x001c,
	DwarfV1_TAG_inlined_subroutine = 0x001d,
	DwarfV1_TAG_module = 0x001e,
	DwarfV1_TAG_ptr_to_member_type = 0x001f,
	DwarfV1_TAG_set_type = 0x0020,
	DwarfV1_TAG_subrange_type = 0x0021,
	DwarfV1_TAG_with_stmt = 0x0022,
	DwarfV1_TAG_lo_user = 0x4080,
	DwarfV1_TAG_hi_user = 0xffff
};

local const uint16_t DWARFV1_FORM_ADDR   = 0x1;
local const uint16_t DWARFV1_FORM_REF    = 0x2;
local const uint16_t DWARFV1_FORM_BLOCK2 = 0x3;
local const uint16_t DWARFV1_FORM_BLOCK4 = 0x4;
local const uint16_t DWARFV1_FORM_DATA2  = 0x5;
local const uint16_t DWARFV1_FORM_DATA4  = 0x6;
local const uint16_t DWARFV1_FORM_DATA8  = 0x7;
local const uint16_t DWARFV1_FORM_STRING = 0x8;

local const uint16_t DWARFV1_FORM_MASK = 0xF;

enum <uint16_t> DwarfV1_AttributeName
{
	DwarfV1_AT_sibling = 0x0010|DWARFV1_FORM_REF,
	DwarfV1_AT_location = 0x0020|DWARFV1_FORM_BLOCK2,
	DwarfV1_AT_name = 0x0030|DWARFV1_FORM_STRING,
	DwarfV1_AT_fund_type = 0x0050|DWARFV1_FORM_DATA2,
	DwarfV1_AT_mod_fund_type = 0x0060|DWARFV1_FORM_BLOCK2,
	DwarfV1_AT_user_def_type = 0x0070|DWARFV1_FORM_REF,
	DwarfV1_AT_mod_u_d_type = 0x0080|DWARFV1_FORM_BLOCK2,
	DwarfV1_AT_ordering = 0x0090|DWARFV1_FORM_DATA2,
	DwarfV1_AT_subscr_data = 0x00a0|DWARFV1_FORM_BLOCK2,
	DwarfV1_AT_byte_size = 0x00b0|DWARFV1_FORM_DATA4,
	DwarfV1_AT_bit_offset = 0x00c0|DWARFV1_FORM_DATA2,
	DwarfV1_AT_bit_size = 0x00d0|DWARFV1_FORM_DATA4,
	DwarfV1_AT_element_list = 0x00f0|DWARFV1_FORM_BLOCK4,
	DwarfV1_AT_stmt_list = 0x0100|DWARFV1_FORM_DATA4,
	DwarfV1_AT_low_pc = 0x0110|DWARFV1_FORM_ADDR,
	DwarfV1_AT_high_pc = 0x0120|DWARFV1_FORM_ADDR,
	DwarfV1_AT_language = 0x0130|DWARFV1_FORM_DATA4,
	DwarfV1_AT_member = 0x0140|DWARFV1_FORM_REF,
	DwarfV1_AT_discr = 0x0150|DWARFV1_FORM_REF,
	DwarfV1_AT_discr_value = 0x0160|DWARFV1_FORM_BLOCK2,
	DwarfV1_AT_string_length = 0x0190|DWARFV1_FORM_BLOCK2,
	DwarfV1_AT_common_reference = 0x01a0|DWARFV1_FORM_REF,
	DwarfV1_AT_comp_dir = 0x01b0|DWARFV1_FORM_STRING,
	DwarfV1_AT_const_value = 0x01c0|DWARFV1_FORM_STRING,
	//DwarfV1_AT_const_value = 0x01c0|DWARFV1_FORM_DATA2,
	//DwarfV1_AT_const_value = 0x01c0|DWARFV1_FORM_DATA4,
	//DwarfV1_AT_const_value = 0x01c0|DWARFV1_FORM_DATA8,
	//DwarfV1_AT_const_value = 0x01c0|DWARFV1_FORM_BLOCK2,
	//DwarfV1_AT_const_value = 0x01c0|DWARFV1_FORM_BLOCK4,
	DwarfV1_AT_containing_type = 0x01d0|DWARFV1_FORM_REF,
	DwarfV1_AT_default_value = 0x01e0|DWARFV1_FORM_ADDR,
	//DwarfV1_AT_default_value = 0x01e0|DWARFV1_FORM_DATA2,
	//DwarfV1_AT_default_value = 0x01e0|DWARFV1_FORM_DATA8,
	//DwarfV1_AT_default_value = 0x01e0|DWARFV1_FORM_STRING,
	DwarfV1_AT_friends = 0x01f0|DWARFV1_FORM_BLOCK2
};

enum <uint16_t> DwarfV1_FundamentalType
{
	DwarfV1_FT_char = 0x0001,
	DwarfV1_FT_signed_char = 0x0002,
	DwarfV1_FT_unsigned_char = 0x0003,
	DwarfV1_FT_short = 0x0004,
	DwarfV1_FT_signed_short = 0x0005,
	DwarfV1_FT_unsigned_short = 0x0006,
	DwarfV1_FT_integer = 0x0007,
	DwarfV1_FT_signed_integer = 0x0008,
	DwarfV1_FT_unsigned_integer = 0x0009,
	DwarfV1_FT_long = 0x000a,
	DwarfV1_FT_signed_long = 0x000b,
	DwarfV1_FT_unsigned_long = 0x000c,
	DwarfV1_FT_pointer = 0x000d,
	DwarfV1_FT_float = 0x000e,
	DwarfV1_FT_dbl_prec_float = 0x000f,
	DwarfV1_FT_ext_prec_float = 0x0010,
	DwarfV1_FT_complex = 0x0011,
	DwarfV1_FT_dbl_prec_complex = 0x0012,
	DwarfV1_FT_void = 0x0014,
	DwarfV1_FT_boolean = 0x0015,
	DwarfV1_FT_ext_prec_complex = 0x0016,
	DwarfV1_FT_label = 0x0017,
	DwarfV1_FT_lo_user = 0x8000,
	DwarfV1_FT_hi_user = 0xffff
};

enum <uint8_t> DwarfV1_TypeModifier
{
	DwarfV1_MOD_pointer_to = 0x01,
	DwarfV1_MOD_reference_to = 0x02,
	DwarfV1_MOD_const = 0x03,
	DwarfV1_MOD_volatile = 0x04,
	DwarfV1_MOD_lo_user = 0x80,
	DwarfV1_MOD_hi_user = 0xff
};

string DwarfV1_FundamentalType_To_String(enum DwarfV1_FundamentalType type)
{
	switch(type)
	{
		case DwarfV1_FT_char:              return "char";
		case DwarfV1_FT_signed_char:       return "signed char";
		case DwarfV1_FT_unsigned_char:     return "unsigned char";
		case DwarfV1_FT_short:             return "short";
		case DwarfV1_FT_signed_short:      return "signed short";
		case DwarfV1_FT_unsigned_short:    return "unsigned short";
		case DwarfV1_FT_integer:           return "int";
		case DwarfV1_FT_signed_integer:    return "signed int";
		case DwarfV1_FT_unsigned_integer:  return "unsigned int";
		case DwarfV1_FT_long:              return "long";
		case DwarfV1_FT_signed_long:       return "signed long";
		case DwarfV1_FT_unsigned_long:     return "unsigned long";
		case DwarfV1_FT_pointer:           return "void*";
		case DwarfV1_FT_float:             return "float";
		case DwarfV1_FT_dbl_prec_float:    return "double";
		case DwarfV1_FT_void:              return "void";
		case DwarfV1_FT_boolean:           return "bool";
		
		default:
			return "???";
	}
}

struct DwarfV1_Attribute(enum ELF_Class ei_class)
{
	enum DwarfV1_AttributeName at_name;
	
	switch(at_name)
	{
		case DwarfV1_AT_fund_type:
			uint16_t fund_type;
			break;
			
		case DwarfV1_AT_mod_fund_type:
			private uint16_t at_data_length;
			enum DwarfV1_TypeModifier modifiers[at_data_length - 2];
			uint16_t fund_type;
			break;
			
		case DwarfV1_AT_user_def_type:
			uint32_t user_def_type;
			break;
			
		case DwarfV1_AT_mod_u_d_type:
			private uint16_t at_data_length;
			enum DwarfV1_TypeModifier modifiers[at_data_length - 4];
			uint32_t user_def_type;
			break;
			
		default:
			switch(at_name & DWARFV1_FORM_MASK)
			{
				case DWARFV1_FORM_ADDR:
					if(ei_class == ELF_CLASS_32BIT)
					{
						uint32_t at_addr;
					}
					else if(ei_class == ELF_CLASS_64BIT)
					{
						uint64_t at_addr;
					}
					
					break;
					
				case DWARFV1_FORM_REF:
					uint32_t at_reference;
					break;
					
				case DWARFV1_FORM_BLOCK2:
					uint16_t at_data_length;
					uint8_t at_data[at_data_length];
					break;
					
				case DWARFV1_FORM_BLOCK4:
					uint32_t at_data_length;
					uint8_t at_data[at_data_length];
					break;
					
				case DWARFV1_FORM_DATA2:
					uint16_t at_constant;
					break;
					
				case DWARFV1_FORM_DATA4:
					uint32_t at_constant;
					break;
					
				case DWARFV1_FORM_DATA8:
					uint64_t at_constant;
					break;
					
				case DWARFV1_FORM_STRING:
					local string s = ReadString();
					char at_string[ StringLengthBytes(s) + 1 ];
					break;
				
				default:
					Error("Unrecognised DWARF attribute type %d", (int)(at_name & DWARFV1_FORM_MASK));
			}
			
			break;
	}
};

uint32_t DwarfV1_FindSiblingAttribute(const struct DwarfV1_Attribute[] &attributes)
{
	for(local int i = 0; i < ArrayLength(attributes); ++i)
	{
		if(attributes[i].at_name == DwarfV1_AT_sibling)
		{
			return attributes[i].at_reference;
		}
	}
	
	return 0xFFFFFFFF;
}

bool DwarfV1_GetStringAttribute(string &out, const struct DwarfV1_Attribute[] &attributes, enum DwarfV1_AttributeName attribute_name)
{
	for(local int i = 0; i < ArrayLength(attributes); ++i)
	{
		if((attributes[i].at_name & ~DWARFV1_FORM_MASK) == (attribute_name & ~DWARFV1_FORM_MASK))
		{
			if((attributes[i].at_name & DWARFV1_FORM_MASK) == DWARFV1_FORM_STRING)
			{
				out = attributes[i].at_string;
				return true;
			}
			else{
				return false;
			}
		}
	}
	
	return false;
}

bool DwarfV1_GetAddressAttribute(uint64_t &out, const struct DwarfV1_Attribute[] &attributes, enum DwarfV1_AttributeName attribute_name)
{
	for(local int i = 0; i < ArrayLength(attributes); ++i)
	{
		if((attributes[i].at_name & ~DWARFV1_FORM_MASK) == (attribute_name & ~DWARFV1_FORM_MASK))
		{
			if((attributes[i].at_name & DWARFV1_FORM_MASK) == DWARFV1_FORM_ADDR)
			{
				out = attributes[i].at_addr;
				return true;
			}
			else{
				return false;
			}
		}
	}
	
	return false;
}

bool DwarfV1_GetReferenceAttribute(uint32_t &out, const struct DwarfV1_Attribute[] &attributes, enum DwarfV1_AttributeName attribute_name)
{
	for(local int i = 0; i < ArrayLength(attributes); ++i)
	{
		if((attributes[i].at_name & ~DWARFV1_FORM_MASK) == (attribute_name & ~DWARFV1_FORM_MASK))
		{
			if((attributes[i].at_name & DWARFV1_FORM_MASK) == DWARFV1_FORM_REF)
			{
				out = attributes[i].at_reference;
				return true;
			}
			else{
				return false;
			}
		}
	}
	
	return false;
}

int64_t DwarfV1_FindAttribute(const struct DwarfV1_Attribute[] &attributes, enum DwarfV1_AttributeName attribute_name)
{
	for(local int64_t i = 0; i < ArrayLength(attributes); ++i)
	{
		if((attributes[i].at_name & ~DWARFV1_FORM_MASK) == (attribute_name & ~DWARFV1_FORM_MASK))
		{
			return i;
		}
	}
	
	return -1;
}

struct DwarfV1_Entry(int64_t debug_section_base, enum ELF_Class ei_class)
{
	local int64_t start = FTell();
	
	uint32_t length;
	
	if(length < 8)
	{
		unsigned char padding[length - 4];
		struct DwarfV1_Attribute attributes[0];
		struct DwarfV1_Entry children[0];
	}
	else{
		uint16_t tag;
		
		local int64_t attrs_end = start + length;
		
		if(tag == DwarfV1_TAG_padding)
		{
			unsigned char padding[length - 6];
			
			struct DwarfV1_Attribute attributes[0];
			struct DwarfV1_Entry children[0];
		}
		else{
			struct DwarfV1_Attribute attributes[0];
			while(FTell() < attrs_end)
			{
				ArrayExtend(attributes, 1, ei_class);
			}
			
			local int64_t children_end = debug_section_base + DwarfV1_FindSiblingAttribute(attributes);
			
			struct DwarfV1_Entry children[0];
			while(FTell() < children_end)
			{
				ArrayExtend(children, 1, debug_section_base, ei_class);
			}
		}
	}
};

bool DwarfV1_GetNameOfEntryAtOffset(string &name, int64_t debug_base_offset, int64_t debug_entry_offset, enum ELF_Class ei_class)
{
	local int64_t saved_offset = FTell();
	
	FSeek(debug_base_offset + debug_entry_offset);
	private struct DwarfV1_Entry entry(debug_base_offset, ei_class);
	
	FSeek(saved_offset);
	
	return DwarfV1_GetStringAttribute(name, entry.attributes, DwarfV1_AT_name);
}

string _DwarfV1_GetModifiedTypeName(enum DwarfV1_TypeModifier[] modifiers, string base_type_name)
{
	local string type_parts[1];
	type_parts[0] = "";
	
	for(local int i = 0; i < ArrayLength(modifiers); ++i)
	{
		local int j = ArrayLength(type_parts) - 1;
		
		switch(modifiers[i])
		{
			case DwarfV1_MOD_pointer_to:
				ArrayPush(type_parts, "*");
				ArrayPush(type_parts, "");
				break;
				
			case DwarfV1_MOD_reference_to:
				ArrayPush(type_parts, "&");
				ArrayPush(type_parts, "");
				break;
				
			case DwarfV1_MOD_const:
				type_parts[j] = type_parts[j] == "" ? "const" : SPrintf("%s const", type_parts[j]);
				break;
				
			case DwarfV1_MOD_volatile:
				type_parts[j] = type_parts[j] == "" ? "volatile" : SPrintf("%s volatile", type_parts[j]);
				break;
		}
	}
	
	local int j = ArrayLength(type_parts) - 1;
	type_parts[j] = type_parts[j] == "" ? base_type_name : SPrintf("%s %s", type_parts[j], base_type_name);
	
	local string type_name = type_parts[0];
	for(local int i = 1; i < ArrayLength(type_parts); ++i)
	{
		type_name = SPrintf("%s %s", type_parts[i], type_name);
	}
	
	return type_name;
}

/* Get the type of an entry (e.g. a function parameter).
 *
 * Searches for an (optionally modified) fundamental or user-defined type
 * attribute and returns the string representation as it might appear in the
 * original C/C++ source code.
*/
string DwarfV1_GetTypeNameOfEntry(const struct DwarfV1_Entry &debug_entry, int64_t debug_section_offset, enum ELF_Class ei_class)
{
	local int64_t attr_idx;
	
	if((attr_idx = DwarfV1_FindAttribute(debug_entry.attributes, DwarfV1_AT_fund_type)) >= 0)
	{
		local string fundamental_type_name = DwarfV1_FundamentalType_To_String(debug_entry.attributes[attr_idx].fund_type);
		return fundamental_type_name;
	}
	else if((attr_idx = DwarfV1_FindAttribute(debug_entry.attributes, DwarfV1_AT_mod_fund_type)) >= 0)
	{
		local string modified_type_name = _DwarfV1_GetModifiedTypeName(
			debug_entry.attributes[attr_idx].modifiers,
			DwarfV1_FundamentalType_To_String(debug_entry.attributes[attr_idx].fund_type));
		
		return modified_type_name;
	}
	else if((attr_idx = DwarfV1_FindAttribute(debug_entry.attributes, DwarfV1_AT_user_def_type)) >= 0)
	{
		local string user_defined_type_name;
		DwarfV1_GetNameOfEntryAtOffset(user_defined_type_name, debug_section_offset, debug_entry.attributes[attr_idx].user_def_type, ei_class);
		
		return user_defined_type_name;
	}
	else if((attr_idx = DwarfV1_FindAttribute(debug_entry.attributes, DwarfV1_AT_mod_u_d_type)) >= 0)
	{
		local string user_defined_type_name;
		DwarfV1_GetNameOfEntryAtOffset(user_defined_type_name, debug_section_offset, debug_entry.attributes[attr_idx].user_def_type, ei_class);
		
		local string modified_type_name = _DwarfV1_GetModifiedTypeName(
			debug_entry.attributes[attr_idx].modifiers,
			user_defined_type_name);
		
		return modified_type_name;
	}
	else{
		return "???";
	}
}

struct DwarfV1(int64_t debug_section_length, enum ELF_Class ei_class)
{
	local int64_t debug_section_base = FTell();
	local int64_t debug_section_end = debug_section_base + debug_section_length;
	
	struct DwarfV1_Entry entries[0];
	while(FTell() < debug_section_end)
	{
		ArrayExtend(entries, 1, debug_section_base, ei_class);
	}
};

#endif /* !DWARF_V1_H */
