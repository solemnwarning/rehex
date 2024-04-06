/* Reverse Engineer's Hex Editor
 * Copyright (C) 2020-2024 Daniel Collins <solemnwarning@solemnwarning.net>
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

#ifndef REHEX_BASICDATATYPES_HPP
#define REHEX_BASICDATATYPES_HPP

#include <assert.h>
#include <exception>
#include <inttypes.h>
#include <stdint.h>
#include <wx/clipbrd.h>
#include <wx/dataobj.h>
#include <wx/utils.h>

#include "DataType.hpp"
#include "document.hpp"
#include "DocumentCtrl.hpp"
#include "FixedSizeValueRegion.hpp"
#include "SharedDocumentPointer.hpp"

namespace REHex
{
	template<typename T> class NumericDataTypeRegion: public FixedSizeValueRegion
	{
		protected:
			NumericDataTypeRegion(SharedDocumentPointer &doc, BitOffset offset, BitOffset length, BitOffset virt_offset, const std::string &type_label):
				FixedSizeValueRegion(doc, offset, length, virt_offset, type_label)
			{
				assert(length == sizeof(T));
			}
	};
	
	#define DECLARE_NDTR_CLASS(NAME, T) \
		class NAME: public NumericDataTypeRegion<T> \
		{ \
			public: \
				NAME(SharedDocumentPointer &doc, REHex::BitOffset offset, REHex::BitOffset length, REHex::BitOffset virt_offset); \
				\
			protected: \
				virtual std::string load_value() const override; \
				virtual bool store_value(const std::string &value) override; \
		};
	
	DECLARE_NDTR_CLASS(U8DataRegion, uint8_t)
	DECLARE_NDTR_CLASS(S8DataRegion, int8_t)
	
	DECLARE_NDTR_CLASS(U16LEDataRegion, uint16_t)
	DECLARE_NDTR_CLASS(U16BEDataRegion, uint16_t)
	DECLARE_NDTR_CLASS(S16LEDataRegion, int16_t)
	DECLARE_NDTR_CLASS(S16BEDataRegion, int16_t)
	
	DECLARE_NDTR_CLASS(U32LEDataRegion, uint32_t)
	DECLARE_NDTR_CLASS(U32BEDataRegion, uint32_t)
	DECLARE_NDTR_CLASS(S32LEDataRegion, int32_t)
	DECLARE_NDTR_CLASS(S32BEDataRegion, int32_t)
	
	DECLARE_NDTR_CLASS(U64LEDataRegion, uint64_t)
	DECLARE_NDTR_CLASS(U64BEDataRegion, uint64_t)
	DECLARE_NDTR_CLASS(S64LEDataRegion, int64_t)
	DECLARE_NDTR_CLASS(S64BEDataRegion, int64_t)
	
	DECLARE_NDTR_CLASS(F32LEDataRegion, float);
	DECLARE_NDTR_CLASS(F32BEDataRegion, float);
	DECLARE_NDTR_CLASS(F64LEDataRegion, double);
	DECLARE_NDTR_CLASS(F64BEDataRegion, double);
}

#endif /* !REHEX_BASICDATATYPES_HPP */
