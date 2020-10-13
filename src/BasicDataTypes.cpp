/* Reverse Engineer's Hex Editor
 * Copyright (C) 2020 Daniel Collins <solemnwarning@solemnwarning.net>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#include "platform.hpp"

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>

#include "BasicDataTypes.hpp"
#include "DataType.hpp"
#include "document.hpp"
#include "DocumentCtrl.hpp"
#include "NumericTextCtrl.hpp"
#include "SharedDocumentPointer.hpp"

/* This MUST come after the wxWidgets headers have been included, else we pull in windows.h BEFORE the wxWidgets
 * headers when building on Windows and this causes unicode-flavoured pointer conversion errors.
*/
#include <portable_endian.h>

#define IMPLEMENT_NDTR_CLASS(NAME, T, LABEL, FMT, XTOH, HTOX, FACTORY_FUNC) \
	REHex::NAME::NAME(SharedDocumentPointer &doc, off_t offset, off_t length): \
		NumericDataTypeRegion(doc, offset, length, LABEL) {} \
	\
	std::string REHex::NAME::to_string(const T *data) const \
	{ \
		char buf[128]; \
		snprintf(buf, sizeof(buf), FMT, (T)(XTOH(*data))); \
		\
		return std::string(buf); \
	} \
	\
	bool REHex::NAME::write_string_value(const std::string &value) \
	{ \
		T buf; \
		try { \
			buf = NumericTextCtrl::ParseValue<T>(value); \
		} \
		catch(const REHex::NumericTextCtrl::InputError &e) \
		{ \
			return false; \
		} \
		buf = HTOX(buf); \
		doc->overwrite_data(d_offset, &buf, sizeof(buf)); \
		return true; \
	} \
	\
	static REHex::DocumentCtrl::Region *FACTORY_FUNC(REHex::SharedDocumentPointer &doc, off_t offset, off_t length) \
	{ \
		return new REHex::NAME(doc, offset, length); \
	}

IMPLEMENT_NDTR_CLASS(U16LEDataRegion, uint16_t, "u16le", "%" PRIu16, le16toh, htole16, u16le_factory)
IMPLEMENT_NDTR_CLASS(U16BEDataRegion, uint16_t, "u16be", "%" PRIu16, be16toh, htobe16, u16be_factory)
IMPLEMENT_NDTR_CLASS(S16LEDataRegion, int16_t,  "s16le", "%" PRId16, le16toh, htole16, s16le_factory)
IMPLEMENT_NDTR_CLASS(S16BEDataRegion, int16_t,  "s16be", "%" PRId16, be16toh, htobe16, s16be_factory)

static REHex::DataTypeRegistration u16le_dtr("u16le", "unsigned 16-bit (little endian)", &u16le_factory, sizeof(uint16_t));
static REHex::DataTypeRegistration u16be_dtr("u16be", "unsigned 16-bit (big endian)",    &u16be_factory, sizeof(uint16_t));
static REHex::DataTypeRegistration s16le_dtr("s16le", "signed 16-bit (little endian)",   &s16le_factory, sizeof(int16_t));
static REHex::DataTypeRegistration s16be_dtr("s16be", "signed 16-bit (big endian)",      &s16be_factory, sizeof(int16_t));

IMPLEMENT_NDTR_CLASS(U32LEDataRegion, uint32_t, "u32le", "%" PRIu32, le32toh, htole32, u32le_factory)
IMPLEMENT_NDTR_CLASS(U32BEDataRegion, uint32_t, "u32be", "%" PRIu32, be32toh, htobe32, u32be_factory)
IMPLEMENT_NDTR_CLASS(S32LEDataRegion, int32_t,  "s32le", "%" PRId32, le32toh, htole32, s32le_factory)
IMPLEMENT_NDTR_CLASS(S32BEDataRegion, int32_t,  "s32be", "%" PRId32, be32toh, htobe32, s32be_factory)

static REHex::DataTypeRegistration u32le_dtr("u32le", "unsigned 32-bit (little endian)", &u32le_factory, sizeof(uint32_t));
static REHex::DataTypeRegistration u32be_dtr("u32be", "unsigned 32-bit (big endian)",    &u32be_factory, sizeof(uint32_t));
static REHex::DataTypeRegistration s32le_dtr("s32le", "signed 32-bit (little endian)",   &s32le_factory, sizeof(int32_t));
static REHex::DataTypeRegistration s32be_dtr("s32be", "signed 32-bit (big endian)",      &s32be_factory, sizeof(int32_t));

IMPLEMENT_NDTR_CLASS(U64LEDataRegion, uint64_t, "u64le", "%" PRIu64, le64toh, htole64, u64le_factory)
IMPLEMENT_NDTR_CLASS(U64BEDataRegion, uint64_t, "u64be", "%" PRIu64, be64toh, htobe64, u64be_factory)
IMPLEMENT_NDTR_CLASS(S64LEDataRegion, int64_t,  "s64le", "%" PRId64, le64toh, htole64, s64le_factory)
IMPLEMENT_NDTR_CLASS(S64BEDataRegion, int64_t,  "s64be", "%" PRId64, be64toh, htobe64, s64be_factory)

static REHex::DataTypeRegistration u64le_dtr("u64le", "unsigned 64-bit (little endian)", &u64le_factory, sizeof(uint64_t));
static REHex::DataTypeRegistration u64be_dtr("u64be", "unsigned 64-bit (big endian)",    &u64be_factory, sizeof(uint64_t));
static REHex::DataTypeRegistration s64le_dtr("s64le", "signed 64-bit (little endian)",   &s64le_factory, sizeof(int64_t));
static REHex::DataTypeRegistration s64be_dtr("s64be", "signed 64-bit (big endian)",      &s64be_factory, sizeof(int64_t));
