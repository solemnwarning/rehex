/* Reverse Engineer's Hex Editor
 * Copyright (C) 2024 Daniel Collins <solemnwarning@solemnwarning.net>
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

#ifndef REHEX_CUSTOMNUMERICTYPE_HPP
#define REHEX_CUSTOMNUMERICTYPE_HPP

#include <wx/choice.h>
#include <wx/dialog.h>
#include <wx/spinctrl.h>

#include "DataType.hpp"
#include "DocumentCtrl.hpp"
#include "FixedSizeValueRegion.hpp"

namespace REHex
{
	class CustomNumericType
	{
		public:
			enum class BaseType
			{
				UNSIGNED_INT,
				SIGNED_INT,
			};
			
			enum class Endianness
			{
				LITTLE,
				BIG,
			};
			
			/**
			 * @brief Construct a new CustomNumericType.
			 *
			 * @param base_type   The POD type this type represents.
			 * @param endianness  The endianness of this type.
			 * @param bits        The size of a value in this type, in bits.
			 *
			 * NOTE: Currently Endianness::BIG must be specified for any types which
			 * are not a multiple of 8 bits in size.
			*/
			CustomNumericType(BaseType base_type, Endianness endianness, size_t bits);
			
			/**
			 * @brief Construct a previously serialised CustomNumericType.
			*/
			CustomNumericType(const json_t *options);
			
			/**
			 * @brief Get the "base type" of this type.
			 *
			 * The "base type" defines which family of plain data types this type
			 * belongs to.
			*/
			BaseType get_base_type() const;
			
			/**
			 * @brief Get the endianness of this type.
			*/
			Endianness get_endianness() const;
			
			/**
			 * @brief Get the size of this type, in bits.
			*/
			size_t get_bits() const;
			
			/**
			 * @brief Get the human-readable description of this type.
			*/
			std::string get_description() const;
			
			/**
			 * @brief Get a DataType for this CustomNumericType.
			*/
			DataType get_DataType() const;
			
			/**
			 * @brief Decode and format the value as a string.
			*/
			std::string format_value(const std::vector<bool> &data) const;
			
			/**
			 * @brief Parse and encode the value from a string.
			*/
			std::vector<bool> parse_value(const std::string &value) const;
			
		private:
			BaseType base_type;
			Endianness endianness;
			
			size_t bits;
	};
	
	/**
	 * @brief Dialog for configuring a CustomNumericType.
	*/
	class CustomNumericTypeDialog: public wxDialog
	{
		public:
			CustomNumericTypeDialog(wxWindow *parent);
			
			json_t *get_options() const;
			
		private:
			wxChoice *base_type_choice;
			wxChoice *endianness_choice;
			wxSpinCtrl *size_spinctrl;
			
			void OnSizeChange(wxSpinEvent &event);
			
		DECLARE_EVENT_TABLE()
	};
	
	class CustomNumericTypeRegion: public FixedSizeValueRegion
	{
		private:
			CustomNumericType type;
			
		public:
			CustomNumericTypeRegion(SharedDocumentPointer &doc, BitOffset offset, BitOffset length, BitOffset virt_offset, const CustomNumericType &type);
			
		protected:
			virtual std::string load_value() const override;
			virtual bool store_value(const std::string &value) override;
	};
};

#endif /* !REHEX_CUSTOMNUMERICTYPE_HPP */
