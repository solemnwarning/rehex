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

#include "../src/platform.hpp"
#include <gtest/gtest.h>

#include "testutil.hpp"

#include "../src/CustomNumericType.hpp"

using namespace REHex;

TEST(CustomNumericType, FormatUnsigned8Bit)
{
	/* Endianness has no meaning for an 8-bit integer, both are tested here for completeness. */
	
	CustomNumericType u8be(CustomNumericType::BaseType::UNSIGNED_INT, CustomNumericType::Endianness::BIG, 8);
	CustomNumericType u8le(CustomNumericType::BaseType::UNSIGNED_INT, CustomNumericType::Endianness::LITTLE, 8);
	
	EXPECT_EQ(
		u8be.format_value(std::vector<bool>{ 0, 0, 0, 0, 0, 0, 0, 0 }),
		"0");
	
	EXPECT_EQ(
		u8be.format_value(std::vector<bool>{ 0, 0, 0, 0, 0, 1, 0, 1 }),
		"5");
	
	EXPECT_EQ(
		u8le.format_value(std::vector<bool>{ 1, 0, 0, 0, 0, 1, 0, 0 }),
		"132");
}

TEST(CustomNumericType, ParseUnsigned8Bit)
{
	/* Endianness has no meaning for an 8-bit integer, both are tested here for completeness. */
	
	CustomNumericType u8be(CustomNumericType::BaseType::UNSIGNED_INT, CustomNumericType::Endianness::BIG, 8);
	CustomNumericType u8le(CustomNumericType::BaseType::UNSIGNED_INT, CustomNumericType::Endianness::LITTLE, 8);
	
	EXPECT_EQ(
		u8be.parse_value("0"),
		std::vector<bool>({ 0, 0, 0, 0, 0, 0, 0, 0 }));
	
	EXPECT_EQ(
		u8be.parse_value("5"),
		std::vector<bool>({ 0, 0, 0, 0, 0, 1, 0, 1 }));
	
	EXPECT_EQ(
		u8le.parse_value("254"),
		std::vector<bool>({ 1, 1, 1, 1, 1, 1, 1, 0 }));
	
	EXPECT_EQ(
		u8le.parse_value("255"),
		std::vector<bool>({ 1, 1, 1, 1, 1, 1, 1, 1 }));
	
	EXPECT_THROW({ u8le.parse_value("cheese"); }, std::invalid_argument);
	EXPECT_THROW({ u8le.parse_value("-1"); }, std::invalid_argument);
	EXPECT_THROW({ u8le.parse_value("256"); }, std::invalid_argument);
}

TEST(CustomNumericType, FormatSigned8Bit)
{
	/* Endianness has no meaning for an 8-bit integer, both are tested here for completeness. */
	
	CustomNumericType s8be(CustomNumericType::BaseType::SIGNED_INT, CustomNumericType::Endianness::BIG, 8);
	CustomNumericType s8le(CustomNumericType::BaseType::SIGNED_INT, CustomNumericType::Endianness::LITTLE, 8);
	
	EXPECT_EQ(
		s8be.format_value(std::vector<bool>{ 0, 0, 0, 0, 0, 0, 0, 0 }),
		"0");
	
	EXPECT_EQ(
		s8be.format_value(std::vector<bool>{ 0, 0, 0, 0, 0, 1, 0, 1 }),
		"5");
	
	EXPECT_EQ(
		s8be.format_value(std::vector<bool>{ 0, 1, 1, 1, 1, 1, 1, 1 }),
		"127");
	
	EXPECT_EQ(
		s8be.format_value(std::vector<bool>{ 1, 1, 1, 1, 1, 1, 1, 1 }),
		"-1");
	
	EXPECT_EQ(
		s8be.format_value(std::vector<bool>{ 1, 1, 1, 1, 1, 1, 0, 1 }),
		"-3");
	
	EXPECT_EQ(
		s8be.format_value(std::vector<bool>{ 1, 0, 0, 0, 0, 0, 0, 0 }),
		"-128");
}

TEST(CustomNumericType, ParseSigned8Bit)
{
	/* Endianness has no meaning for an 8-bit integer, both are tested here for completeness. */
	
	CustomNumericType s8be(CustomNumericType::BaseType::SIGNED_INT, CustomNumericType::Endianness::BIG, 8);
	CustomNumericType s8le(CustomNumericType::BaseType::SIGNED_INT, CustomNumericType::Endianness::LITTLE, 8);
	
	EXPECT_EQ(
		s8be.parse_value("0"),
		std::vector<bool>({ 0, 0, 0, 0, 0, 0, 0, 0 }));
	
	EXPECT_EQ(
		s8be.parse_value("5"),
		std::vector<bool>({ 0, 0, 0, 0, 0, 1, 0, 1 }));
	
	EXPECT_EQ(
		s8le.parse_value("127"),
		std::vector<bool>({ 0, 1, 1, 1, 1, 1, 1, 1 }));
	
	EXPECT_THROW({ s8le.parse_value("128"); }, std::invalid_argument);
	
	EXPECT_EQ(
		s8le.parse_value("-1"),
		std::vector<bool>({ 1, 1, 1, 1, 1, 1, 1, 1 }));
	
	EXPECT_EQ(
		s8le.parse_value("-3"),
		std::vector<bool>({ 1, 1, 1, 1, 1, 1, 0, 1 }));
	
	EXPECT_EQ(
		s8le.parse_value("-128"),
		std::vector<bool>({ 1, 0, 0, 0, 0, 0, 0, 0 }));
	
	EXPECT_THROW({ s8le.parse_value("-129"); }, std::invalid_argument);
	
	EXPECT_THROW({ s8le.parse_value("cheese"); }, std::invalid_argument);
}

TEST(CustomNumericType, FormatUnsigned24Bit)
{
	CustomNumericType u24be(CustomNumericType::BaseType::UNSIGNED_INT, CustomNumericType::Endianness::BIG, 24);
	CustomNumericType u24le(CustomNumericType::BaseType::UNSIGNED_INT, CustomNumericType::Endianness::LITTLE, 24);
	
	EXPECT_EQ(
		u24be.format_value(std::vector<bool>{
			0, 0, 0, 0, 0, 0, 0, 0, /* MSB */
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, /* LSB */ }),
		"0");
	
	EXPECT_EQ(
		u24le.format_value(std::vector<bool>{
			0, 0, 0, 0, 0, 0, 0, 0, /* LSB */
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, /* MSB */ }),
		"0");
	
	EXPECT_EQ(
		u24be.format_value(std::vector<bool>{
			0, 0, 0, 0, 0, 0, 0, 0, /* MSB */
			0, 0, 0, 0, 0, 0, 0, 0,
			1, 1, 1, 1, 1, 1, 1, 1, /* LSB */ }),
		"255");
	
	EXPECT_EQ(
		u24le.format_value(std::vector<bool>{
			1, 1, 1, 1, 1, 1, 1, 1, /* LSB */
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, /* MSB */ }),
		"255");
	
	EXPECT_EQ(
		u24be.format_value(std::vector<bool>{
			0, 0, 0, 0, 0, 0, 0, 0, /* MSB */
			0, 0, 0, 0, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1, /* LSB */ }),
		"4095");
	
	EXPECT_EQ(
		u24le.format_value(std::vector<bool>{
			1, 1, 1, 1, 1, 1, 1, 1, /* LSB */
			0, 0, 0, 0, 1, 1, 1, 1,
			0, 0, 0, 0, 0, 0, 0, 0, /* MSB */ }),
		"4095");
	
	EXPECT_EQ(
		u24be.format_value(std::vector<bool>{
			1, 1, 1, 1, 1, 1, 1, 1, /* MSB */
			1, 1, 1, 1, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, /* LSB */ }),
		"16773120");
	
	EXPECT_EQ(
		u24le.format_value(std::vector<bool>{
			0, 0, 0, 0, 0, 0, 0, 0, /* LSB */
			1, 1, 1, 1, 0, 0, 0, 0,
			1, 1, 1, 1, 1, 1, 1, 1, /* MSB */ }),
		"16773120");
	
	EXPECT_EQ(
		u24be.format_value(std::vector<bool>{
			1, 1, 1, 1, 1, 1, 1, 1, /* MSB */
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1, /* LSB */ }),
		"16777215");
	
	EXPECT_EQ(
		u24le.format_value(std::vector<bool>{
			1, 1, 1, 1, 1, 1, 1, 1, /* LSB */
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1, /* MSB */ }),
		"16777215");
}

TEST(CustomNumericType, ParseUnsigned24Bit)
{
	CustomNumericType u24be(CustomNumericType::BaseType::UNSIGNED_INT, CustomNumericType::Endianness::BIG, 24);
	CustomNumericType u24le(CustomNumericType::BaseType::UNSIGNED_INT, CustomNumericType::Endianness::LITTLE, 24);
	
	EXPECT_EQ(
		u24be.parse_value("0"),
		std::vector<bool>({
			0, 0, 0, 0, 0, 0, 0, 0, /* MSB */
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, /* LSB */ }));
	
	EXPECT_EQ(
		u24le.parse_value("0"),
		std::vector<bool>({
			0, 0, 0, 0, 0, 0, 0, 0, /* LSB */
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, /* MSB */ }));
	
	EXPECT_EQ(
		u24be.parse_value("254"),
		std::vector<bool>({
			0, 0, 0, 0, 0, 0, 0, 0, /* MSB */
			0, 0, 0, 0, 0, 0, 0, 0,
			1, 1, 1, 1, 1, 1, 1, 0, /* LSB */ }));
	
	EXPECT_EQ(
		u24le.parse_value("1"),
		std::vector<bool>({
			0, 0, 0, 0, 0, 0, 0, 1, /* LSB */
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, /* MSB */ }));
	
	EXPECT_EQ(
		u24be.parse_value("16773120"),
		std::vector<bool>({
			1, 1, 1, 1, 1, 1, 1, 1, /* MSB */
			1, 1, 1, 1, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, /* LSB */ }));
	
	EXPECT_EQ(
		u24le.parse_value("16773120"),
		std::vector<bool>({
			0, 0, 0, 0, 0, 0, 0, 0, /* LSB */
			1, 1, 1, 1, 0, 0, 0, 0,
			1, 1, 1, 1, 1, 1, 1, 1, /* MSB */ }));
	
	EXPECT_EQ(
		u24be.parse_value("16777215"),
		std::vector<bool>({
			1, 1, 1, 1, 1, 1, 1, 1, /* MSB */
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1, /* LSB */ }));
	
	EXPECT_EQ(
		u24le.parse_value("16777215"),
		std::vector<bool>({
			1, 1, 1, 1, 1, 1, 1, 1, /* LSB */
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1, /* MSB */ }));
	
	EXPECT_THROW({ u24le.parse_value("cheese"); }, std::invalid_argument);
	EXPECT_THROW({ u24le.parse_value("-1"); }, std::invalid_argument);
	EXPECT_THROW({ u24le.parse_value("16777216"); }, std::invalid_argument);
}

TEST(CustomNumericType, FormatSigned24Bit)
{
	CustomNumericType s24be(CustomNumericType::BaseType::SIGNED_INT, CustomNumericType::Endianness::BIG, 24);
	CustomNumericType s24le(CustomNumericType::BaseType::SIGNED_INT, CustomNumericType::Endianness::LITTLE, 24);
	
	EXPECT_EQ(
		s24be.format_value(std::vector<bool>{
			0, 0, 0, 0, 0, 0, 0, 0, /* MSB */
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, /* LSB */ }),
		"0");
	
	EXPECT_EQ(
		s24le.format_value(std::vector<bool>{
			0, 0, 0, 0, 0, 0, 0, 0, /* LSB */
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, /* MSB */ }),
		"0");
	
	EXPECT_EQ(
		s24be.format_value(std::vector<bool>{
			0, 0, 0, 0, 0, 0, 0, 0, /* MSB */
			0, 0, 0, 0, 0, 0, 0, 0,
			1, 1, 1, 1, 1, 1, 1, 1, /* LSB */ }),
		"255");
	
	EXPECT_EQ(
		s24le.format_value(std::vector<bool>{
			1, 1, 1, 1, 1, 1, 1, 1, /* LSB */
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, /* MSB */ }),
		"255");
	
	EXPECT_EQ(
		s24be.format_value(std::vector<bool>{
			0, 0, 0, 0, 0, 0, 0, 0, /* MSB */
			0, 0, 0, 0, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1, /* LSB */ }),
		"4095");
	
	EXPECT_EQ(
		s24le.format_value(std::vector<bool>{
			1, 1, 1, 1, 1, 1, 1, 1, /* LSB */
			0, 0, 0, 0, 1, 1, 1, 1,
			0, 0, 0, 0, 0, 0, 0, 0, /* MSB */ }),
		"4095");
	
	EXPECT_EQ(
		s24be.format_value(std::vector<bool>{
			0, 1, 1, 1, 1, 1, 1, 1, /* MSB */
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1, /* LSB */ }),
		"8388607");
	
	EXPECT_EQ(
		s24le.format_value(std::vector<bool>{
			1, 1, 1, 1, 1, 1, 1, 1, /* LSB */
			1, 1, 1, 1, 1, 1, 1, 1,
			0, 1, 1, 1, 1, 1, 1, 1, /* MSB */ }),
		"8388607");
	
	EXPECT_EQ(
		s24be.format_value(std::vector<bool>{
			1, 1, 1, 1, 1, 1, 1, 1, /* MSB */
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1, /* LSB */ }),
		"-1");
	
	EXPECT_EQ(
		s24le.format_value(std::vector<bool>{
			1, 1, 1, 1, 1, 1, 1, 1, /* LSB */
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1, /* MSB */ }),
		"-1");
	
	EXPECT_EQ(
		s24be.format_value(std::vector<bool>{
			1, 1, 1, 1, 1, 1, 1, 1, /* MSB */
			1, 1, 1, 1, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 1, /* LSB */ }),
		"-4095");
	
	EXPECT_EQ(
		s24le.format_value(std::vector<bool>{
			0, 0, 0, 0, 0, 0, 0, 1, /* LSB */
			1, 1, 1, 1, 0, 0, 0, 0,
			1, 1, 1, 1, 1, 1, 1, 1, /* MSB */ }),
		"-4095");
	
	EXPECT_EQ(
		s24be.format_value(std::vector<bool>{
			1, 0, 0, 0, 0, 0, 0, 0, /* MSB */
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, /* LSB */ }),
		"-8388608");
	
	EXPECT_EQ(
		s24le.format_value(std::vector<bool>{
			0, 0, 0, 0, 0, 0, 0, 0, /* LSB */
			0, 0, 0, 0, 0, 0, 0, 0,
			1, 0, 0, 0, 0, 0, 0, 0, /* MSB */ }),
		"-8388608");
}

TEST(CustomNumericType, ParseSigned24Bit)
{
	CustomNumericType s24be(CustomNumericType::BaseType::SIGNED_INT, CustomNumericType::Endianness::BIG, 24);
	CustomNumericType s24le(CustomNumericType::BaseType::SIGNED_INT, CustomNumericType::Endianness::LITTLE, 24);
	
	EXPECT_EQ(
		s24be.parse_value("0"),
		std::vector<bool>({
			0, 0, 0, 0, 0, 0, 0, 0, /* MSB */
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, /* LSB */ }));
	
	EXPECT_EQ(
		s24le.parse_value("0"),
		std::vector<bool>({
			0, 0, 0, 0, 0, 0, 0, 0, /* LSB */
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, /* MSB */ }));
	
	EXPECT_EQ(
		s24be.parse_value("254"),
		std::vector<bool>({
			0, 0, 0, 0, 0, 0, 0, 0, /* MSB */
			0, 0, 0, 0, 0, 0, 0, 0,
			1, 1, 1, 1, 1, 1, 1, 0, /* LSB */ }));
	
	EXPECT_EQ(
		s24le.parse_value("1"),
		std::vector<bool>({
			0, 0, 0, 0, 0, 0, 0, 1, /* LSB */
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, /* MSB */ }));
	
	EXPECT_EQ(
		s24be.parse_value("8384512"),
		std::vector<bool>({
			0, 1, 1, 1, 1, 1, 1, 1, /* MSB */
			1, 1, 1, 1, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, /* LSB */ }));
	
	EXPECT_EQ(
		s24le.parse_value("8384512"),
		std::vector<bool>({
			0, 0, 0, 0, 0, 0, 0, 0, /* LSB */
			1, 1, 1, 1, 0, 0, 0, 0,
			0, 1, 1, 1, 1, 1, 1, 1, /* MSB */ }));
	
	EXPECT_EQ(
		s24be.parse_value("8388607"),
		std::vector<bool>({
			0, 1, 1, 1, 1, 1, 1, 1, /* MSB */
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1, /* LSB */ }));
	
	EXPECT_EQ(
		s24le.parse_value("8388607"),
		std::vector<bool>({
			1, 1, 1, 1, 1, 1, 1, 1, /* LSB */
			1, 1, 1, 1, 1, 1, 1, 1,
			0, 1, 1, 1, 1, 1, 1, 1, /* MSB */ }));
	
	EXPECT_THROW({ s24be.parse_value("8388608"); }, std::invalid_argument);
	EXPECT_THROW({ s24le.parse_value("8388608"); }, std::invalid_argument);
	
	EXPECT_EQ(
		s24be.parse_value("-1"),
		std::vector<bool>({
			1, 1, 1, 1, 1, 1, 1, 1, /* MSB */
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1, /* LSB */ }));
	
	EXPECT_EQ(
		s24le.parse_value("-1"),
		std::vector<bool>({
			1, 1, 1, 1, 1, 1, 1, 1, /* LSB */
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1, /* MSB */ }));
	
	EXPECT_EQ(
		s24be.parse_value("-4095"),
		std::vector<bool>({
			1, 1, 1, 1, 1, 1, 1, 1, /* MSB */
			1, 1, 1, 1, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 1, /* LSB */ }));
	
	EXPECT_EQ(
		s24le.parse_value("-4095"),
		std::vector<bool>({
			0, 0, 0, 0, 0, 0, 0, 1, /* LSB */
			1, 1, 1, 1, 0, 0, 0, 0,
			1, 1, 1, 1, 1, 1, 1, 1, /* MSB */ }));
	
	EXPECT_EQ(
		s24be.parse_value("-8388608"),
		std::vector<bool>({
			1, 0, 0, 0, 0, 0, 0, 0, /* MSB */
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, /* LSB */ }));
	
	EXPECT_EQ(
		s24le.parse_value("-8388608"),
		std::vector<bool>({
			0, 0, 0, 0, 0, 0, 0, 0, /* LSB */
			0, 0, 0, 0, 0, 0, 0, 0,
			1, 0, 0, 0, 0, 0, 0, 0, /* MSB */ }));
	
	EXPECT_THROW({ s24be.parse_value("-8388609"); }, std::invalid_argument);
	EXPECT_THROW({ s24le.parse_value("-8388609"); }, std::invalid_argument);
	
	EXPECT_THROW({ s24le.parse_value("cheese"); }, std::invalid_argument);
}

TEST(CustomNumericType, FormatUnsigned32Bit)
{
	CustomNumericType u32be(CustomNumericType::BaseType::UNSIGNED_INT, CustomNumericType::Endianness::BIG, 32);
	CustomNumericType u32le(CustomNumericType::BaseType::UNSIGNED_INT, CustomNumericType::Endianness::LITTLE, 32);
	
	EXPECT_EQ(
		u32be.format_value(std::vector<bool>{
			0, 0, 0, 0, 0, 0, 0, 0, /* MSB */
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, /* LSB */ }),
		"0");
	
	EXPECT_EQ(
		u32le.format_value(std::vector<bool>{
			0, 0, 0, 0, 0, 0, 0, 0, /* LSB */
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, /* MSB */ }),
		"0");
	
	EXPECT_EQ(
		u32be.format_value(std::vector<bool>{
			0, 0, 0, 0, 0, 0, 0, 0, /* MSB */
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 1, 0, /* LSB */ }),
		"2");
	
	EXPECT_EQ(
		u32le.format_value(std::vector<bool>{
			0, 0, 0, 0, 0, 1, 0, 1, /* LSB */
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, /* MSB */ }),
		"5");
	
	EXPECT_EQ(
		u32be.format_value(std::vector<bool>{
			1, 0, 0, 0, 0, 0, 0, 0, /* MSB */
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, /* LSB */ }),
		"2147483648");
	
	EXPECT_EQ(
		u32le.format_value(std::vector<bool>{
			0, 0, 0, 0, 0, 0, 0, 0, /* LSB */
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			1, 0, 0, 0, 0, 0, 0, 0, /* MSB */ }),
		"2147483648");
	
	EXPECT_EQ(
		u32be.format_value(std::vector<bool>{
			1, 1, 1, 1, 1, 1, 1, 1, /* MSB */
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1, /* LSB */ }),
		"4294967295");
	
	EXPECT_EQ(
		u32le.format_value(std::vector<bool>{
			1, 1, 1, 1, 1, 1, 1, 1, /* LSB */
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1, /* MSB */ }),
		"4294967295");
	
	EXPECT_EQ(
		u32be.format_value(std::vector<bool>{
			1, 1, 1, 1, 1, 1, 1, 1, /* MSB */
			1, 1, 1, 1, 1, 1, 1, 1,
			0, 0, 0, 0, 0, 0, 0, 0,
			1, 1, 1, 1, 1, 1, 1, 1, /* LSB */ }),
		"4294902015");
	
	EXPECT_EQ(
		u32le.format_value(std::vector<bool>{
			1, 1, 1, 1, 1, 1, 1, 1, /* LSB */
			0, 0, 0, 0, 0, 0, 0, 0,
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1, /* MSB */ }),
		"4294902015");
}

TEST(CustomNumericType, FormatUnsigned14Bit)
{
	CustomNumericType u14be(CustomNumericType::BaseType::UNSIGNED_INT, CustomNumericType::Endianness::BIG, 14);
	
	EXPECT_EQ(
		u14be.format_value(std::vector<bool>{
			      0, 0, 0, 0, 0, 0, /* MSB */
			0, 0, 0, 0, 0, 0, 0, 0, /* LSB */ }),
		"0");
	
	EXPECT_EQ(
		u14be.format_value(std::vector<bool>{
			      0, 0, 0, 0, 0, 0, /* MSB */
			1, 1, 1, 1, 1, 1, 1, 0, /* LSB */ }),
		"254");
	
	EXPECT_EQ(
		u14be.format_value(std::vector<bool>{
			      1, 1, 1, 1, 1, 1, /* MSB */
			1, 1, 1, 1, 1, 1, 1, 1, /* LSB */ }),
		"16383");
	
	EXPECT_EQ(
		u14be.format_value(std::vector<bool>{
			      0, 1, 1, 1, 1, 1, /* MSB */
			1, 1, 1, 1, 1, 1, 1, 0, /* LSB */ }),
		"8190");
}

TEST(CustomNumericType, ParseUnsigned14Bit)
{
	CustomNumericType u14be(CustomNumericType::BaseType::UNSIGNED_INT, CustomNumericType::Endianness::BIG, 14);
	
	EXPECT_EQ(
		u14be.parse_value("0"),
		std::vector<bool>({
			      0, 0, 0, 0, 0, 0, /* MSB */
			0, 0, 0, 0, 0, 0, 0, 0, /* LSB */ }));
	
	EXPECT_EQ(
		u14be.parse_value("254"),
		std::vector<bool>({
			      0, 0, 0, 0, 0, 0, /* MSB */
			1, 1, 1, 1, 1, 1, 1, 0, /* LSB */ }));
	
	EXPECT_EQ(
		u14be.parse_value("16383"),
		std::vector<bool>({
			      1, 1, 1, 1, 1, 1, /* MSB */
			1, 1, 1, 1, 1, 1, 1, 1, /* LSB */ }));
	
	EXPECT_EQ(
		u14be.parse_value("7934"),
		std::vector<bool>({
			      0, 1, 1, 1, 1, 0, /* MSB */
			1, 1, 1, 1, 1, 1, 1, 0, /* LSB */ }));
	
	EXPECT_THROW({ u14be.parse_value("cheese"); }, std::invalid_argument);
	EXPECT_THROW({ u14be.parse_value("-1"); }, std::invalid_argument);
	EXPECT_THROW({ u14be.parse_value("16384"); }, std::invalid_argument);
}

TEST(CustomNumericType, FormatUnsigned64Bit)
{
	CustomNumericType u64be(CustomNumericType::BaseType::UNSIGNED_INT, CustomNumericType::Endianness::BIG, 64);
	CustomNumericType u64le(CustomNumericType::BaseType::UNSIGNED_INT, CustomNumericType::Endianness::LITTLE, 64);
	
	EXPECT_EQ(
		u64be.format_value(std::vector<bool>{
			0, 0, 0, 0, 0, 0, 0, 0, /* MSB */
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, /* LSB */ }),
		"0");
	
	EXPECT_EQ(
		u64le.format_value(std::vector<bool>{
			0, 0, 0, 0, 0, 0, 0, 0, /* LSB */
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, /* MSB */ }),
		"0");
	
	EXPECT_EQ(
		u64be.format_value(std::vector<bool>{
			0, 0, 0, 0, 0, 0, 0, 0, /* MSB */
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 1, 0, /* LSB */ }),
		"2");
	
	EXPECT_EQ(
		u64le.format_value(std::vector<bool>{
			0, 0, 0, 0, 0, 1, 0, 1, /* LSB */
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, /* MSB */ }),
		"5");
	
	EXPECT_EQ(
		u64be.format_value(std::vector<bool>{
			0, 0, 0, 0, 0, 0, 0, 0, /* MSB */
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			1, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, /* LSB */ }),
		"2147483648");
	
	EXPECT_EQ(
		u64le.format_value(std::vector<bool>{
			0, 0, 0, 0, 0, 0, 0, 0, /* LSB */
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			1, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, /* MSB */ }),
		"2147483648");
	
	EXPECT_EQ(
		u64be.format_value(std::vector<bool>{
			0, 0, 0, 0, 0, 0, 0, 0, /* MSB */
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1, /* LSB */ }),
		"4294967295");
	
	EXPECT_EQ(
		u64le.format_value(std::vector<bool>{
			1, 1, 1, 1, 1, 1, 1, 1, /* LSB */
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, /* MSB */ }),
		"4294967295");
	
	EXPECT_EQ(
		u64be.format_value(std::vector<bool>{
			1, 0, 0, 0, 0, 0, 0, 0, /* MSB */
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, /* LSB */ }),
		"9223372036854775808");
	
	EXPECT_EQ(
		u64le.format_value(std::vector<bool>{
			0, 0, 0, 0, 0, 0, 0, 0, /* LSB */
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			1, 0, 0, 0, 0, 0, 0, 0, /* MSB */ }),
		"9223372036854775808");
	
	EXPECT_EQ(
		u64be.format_value(std::vector<bool>{
			1, 1, 1, 1, 1, 1, 1, 1, /* MSB */
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1, /* LSB */ }),
		"18446744073709551615");
	
	EXPECT_EQ(
		u64le.format_value(std::vector<bool>{
			1, 1, 1, 1, 1, 1, 1, 1, /* LSB */
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1, /* MSB */ }),
		"18446744073709551615");
}

TEST(CustomNumericType, ParseUnsigned64Bit)
{
	CustomNumericType u64be(CustomNumericType::BaseType::UNSIGNED_INT, CustomNumericType::Endianness::BIG, 64);
	CustomNumericType u64le(CustomNumericType::BaseType::UNSIGNED_INT, CustomNumericType::Endianness::LITTLE, 64);
	
	EXPECT_EQ(
		u64be.parse_value("0"),
		std::vector<bool>({
			0, 0, 0, 0, 0, 0, 0, 0, /* MSB */
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, /* LSB */ }));
	
	EXPECT_EQ(
		u64le.parse_value("0"),
		std::vector<bool>({
			0, 0, 0, 0, 0, 0, 0, 0, /* LSB */
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, /* MSB */ }));
	
	EXPECT_EQ(
		u64be.parse_value("2"),
		std::vector<bool>({
			0, 0, 0, 0, 0, 0, 0, 0, /* MSB */
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 1, 0, /* LSB */ }));
	
	EXPECT_EQ(
		u64le.parse_value("5"),
		std::vector<bool>({
			0, 0, 0, 0, 0, 1, 0, 1, /* LSB */
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, /* MSB */ }));
	
	EXPECT_EQ(
		u64be.parse_value("2147483648"),
		std::vector<bool>({
			0, 0, 0, 0, 0, 0, 0, 0, /* MSB */
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			1, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, /* LSB */ }));
	
	EXPECT_EQ(
		u64le.parse_value("2147483648"),
		std::vector<bool>({
			0, 0, 0, 0, 0, 0, 0, 0, /* LSB */
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			1, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, /* MSB */ }));
	
	EXPECT_EQ(
		u64be.parse_value("4294967295"),
		std::vector<bool>({
			0, 0, 0, 0, 0, 0, 0, 0, /* MSB */
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1, /* LSB */ }));
	
	EXPECT_EQ(
		u64le.parse_value("4294967295"),
		std::vector<bool>({
			1, 1, 1, 1, 1, 1, 1, 1, /* LSB */
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, /* MSB */ }));
	
	EXPECT_EQ(
		u64be.parse_value("9223372036854775808"),
		std::vector<bool>({
			1, 0, 0, 0, 0, 0, 0, 0, /* MSB */
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, /* LSB */ }));
	
	EXPECT_EQ(
		u64le.parse_value("9223372036854775808"),
		std::vector<bool>({
			0, 0, 0, 0, 0, 0, 0, 0, /* LSB */
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			1, 0, 0, 0, 0, 0, 0, 0, /* MSB */ }));
	
	EXPECT_EQ(
		u64be.parse_value("18446744073709551615"),
		std::vector<bool>({
			1, 1, 1, 1, 1, 1, 1, 1, /* MSB */
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1, /* LSB */ }));
	
	EXPECT_EQ(
		u64le.parse_value("18446744073709551615"),
		std::vector<bool>({
			1, 1, 1, 1, 1, 1, 1, 1, /* LSB */
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1, /* MSB */ }));
	
	EXPECT_THROW({ u64le.parse_value("cheese"); }, std::invalid_argument);
	EXPECT_THROW({ u64le.parse_value("-1"); }, std::invalid_argument);
	EXPECT_THROW({ u64le.parse_value("18446744073709551616"); }, std::invalid_argument);
}

TEST(CustomNumericType, FormatSigned64Bit)
{
	CustomNumericType s64be(CustomNumericType::BaseType::SIGNED_INT, CustomNumericType::Endianness::BIG, 64);
	CustomNumericType s64le(CustomNumericType::BaseType::SIGNED_INT, CustomNumericType::Endianness::LITTLE, 64);
	
	EXPECT_EQ(
		s64be.format_value(std::vector<bool>{
			0, 0, 0, 0, 0, 0, 0, 0, /* MSB */
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, /* LSB */ }),
		"0");
	
	EXPECT_EQ(
		s64le.format_value(std::vector<bool>{
			0, 0, 0, 0, 0, 0, 0, 0, /* LSB */
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, /* MSB */ }),
		"0");
	
	EXPECT_EQ(
		s64be.format_value(std::vector<bool>{
			0, 0, 0, 0, 0, 0, 0, 0, /* MSB */
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 1, 0, /* LSB */ }),
		"2");
	
	EXPECT_EQ(
		s64le.format_value(std::vector<bool>{
			0, 0, 0, 0, 0, 1, 0, 1, /* LSB */
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, /* MSB */ }),
		"5");
	
	EXPECT_EQ(
		s64be.format_value(std::vector<bool>{
			0, 0, 0, 0, 0, 0, 0, 0, /* MSB */
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			1, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, /* LSB */ }),
		"2147483648");
	
	EXPECT_EQ(
		s64le.format_value(std::vector<bool>{
			0, 0, 0, 0, 0, 0, 0, 0, /* LSB */
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			1, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, /* MSB */ }),
		"2147483648");
	
	EXPECT_EQ(
		s64be.format_value(std::vector<bool>{
			0, 0, 0, 0, 0, 0, 0, 0, /* MSB */
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1, /* LSB */ }),
		"4294967295");
	
	EXPECT_EQ(
		s64le.format_value(std::vector<bool>{
			1, 1, 1, 1, 1, 1, 1, 1, /* LSB */
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, /* MSB */ }),
		"4294967295");
	
	EXPECT_EQ(
		s64be.format_value(std::vector<bool>{
			1, 1, 1, 1, 1, 1, 1, 1, /* MSB */
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 0, 0, 1, 1, 1, 0, 0, /* LSB */ }),
		"-100");
	
	EXPECT_EQ(
		s64le.format_value(std::vector<bool>{
			1, 0, 0, 1, 1, 1, 0, 0, /* LSB */
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1, /* MSB */ }),
		"-100");
	
	EXPECT_EQ(
		s64be.format_value(std::vector<bool>{
			1, 0, 0, 0, 0, 0, 0, 0, /* MSB */
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, /* LSB */ }),
		"-9223372036854775808");
	
	EXPECT_EQ(
		s64le.format_value(std::vector<bool>{
			0, 0, 0, 0, 0, 0, 0, 0, /* LSB */
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			1, 0, 0, 0, 0, 0, 0, 0, /* MSB */ }),
		"-9223372036854775808");
	
	EXPECT_EQ(
		s64be.format_value(std::vector<bool>{
			1, 1, 1, 1, 1, 1, 1, 1, /* MSB */
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1, /* LSB */ }),
		"-1");
	
	EXPECT_EQ(
		s64le.format_value(std::vector<bool>{
			1, 1, 1, 1, 1, 1, 1, 1, /* LSB */
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1, /* MSB */ }),
		"-1");
}

TEST(CustomNumericType, ParseSigned64Bit)
{
	CustomNumericType s64be(CustomNumericType::BaseType::SIGNED_INT, CustomNumericType::Endianness::BIG, 64);
	CustomNumericType s64le(CustomNumericType::BaseType::SIGNED_INT, CustomNumericType::Endianness::LITTLE, 64);
	
	EXPECT_EQ(
		s64be.parse_value("0"),
		std::vector<bool>({
			0, 0, 0, 0, 0, 0, 0, 0, /* MSB */
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, /* LSB */ }));
	
	EXPECT_EQ(
		s64le.parse_value("0"),
		std::vector<bool>({
			0, 0, 0, 0, 0, 0, 0, 0, /* LSB */
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, /* MSB */ }));
	
	EXPECT_EQ(
		s64be.parse_value("2"),
		std::vector<bool>({
			0, 0, 0, 0, 0, 0, 0, 0, /* MSB */
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 1, 0, /* LSB */ }));
	
	EXPECT_EQ(
		s64le.parse_value("5"),
		std::vector<bool>({
			0, 0, 0, 0, 0, 1, 0, 1, /* LSB */
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, /* MSB */ }));
	
	EXPECT_EQ(
		s64be.parse_value("2147483648"),
		std::vector<bool>({
			0, 0, 0, 0, 0, 0, 0, 0, /* MSB */
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			1, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, /* LSB */ }));
	
	EXPECT_EQ(
		s64le.parse_value("2147483648"),
		std::vector<bool>({
			0, 0, 0, 0, 0, 0, 0, 0, /* LSB */
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			1, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, /* MSB */ }));
	
	EXPECT_EQ(
		s64be.parse_value("4294967295"),
		std::vector<bool>({
			0, 0, 0, 0, 0, 0, 0, 0, /* MSB */
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1, /* LSB */ }));
	
	EXPECT_EQ(
		s64le.parse_value("4294967295"),
		std::vector<bool>({
			1, 1, 1, 1, 1, 1, 1, 1, /* LSB */
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, /* MSB */ }));
	
	EXPECT_EQ(
		s64be.parse_value("-9223372036854775808"),
		std::vector<bool>({
			1, 0, 0, 0, 0, 0, 0, 0, /* MSB */
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, /* LSB */ }));
	
	EXPECT_EQ(
		s64le.parse_value("-9223372036854775808"),
		std::vector<bool>({
			0, 0, 0, 0, 0, 0, 0, 0, /* LSB */
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			1, 0, 0, 0, 0, 0, 0, 0, /* MSB */ }));
	
	EXPECT_THROW({ s64be.parse_value("-9223372036854775809"); }, std::invalid_argument);
	EXPECT_THROW({ s64le.parse_value("-9223372036854775809"); }, std::invalid_argument);
	
	EXPECT_EQ(
		s64be.parse_value("9223372036854775807"),
		std::vector<bool>({
			0, 1, 1, 1, 1, 1, 1, 1, /* MSB */
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1, /* LSB */ }));
	
	EXPECT_EQ(
		s64le.parse_value("9223372036854775807"),
		std::vector<bool>({
			1, 1, 1, 1, 1, 1, 1, 1, /* LSB */
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1,
			1, 1, 1, 1, 1, 1, 1, 1,
			0, 1, 1, 1, 1, 1, 1, 1, /* MSB */ }));
	
	EXPECT_THROW({ s64be.parse_value("9223372036854775808"); }, std::invalid_argument);
	EXPECT_THROW({ s64le.parse_value("9223372036854775808"); }, std::invalid_argument);
	
	EXPECT_THROW({ s64le.parse_value("cheese"); }, std::invalid_argument);
}

TEST(CustomNumericType, DeserialiseLittleEndianUnsigned)
{
	CustomNumericType type(AutoJSON("{ \"base-type\": \"UNSIGNED_INT\", \"endianness\": \"LITTLE\", \"bits\": 24 }").json);
	
	EXPECT_EQ(type.get_base_type(), CustomNumericType::BaseType::UNSIGNED_INT);
	EXPECT_EQ(type.get_endianness(), CustomNumericType::Endianness::LITTLE);
	EXPECT_EQ(type.get_bits(), 24U);
}

TEST(CustomNumericType, DeserialiseBigEndianUnsigned)
{
	CustomNumericType type(AutoJSON("{ \"base-type\": \"UNSIGNED_INT\", \"endianness\": \"BIG\", \"bits\": 24 }").json);
	
	EXPECT_EQ(type.get_base_type(), CustomNumericType::BaseType::UNSIGNED_INT);
	EXPECT_EQ(type.get_endianness(), CustomNumericType::Endianness::BIG);
	EXPECT_EQ(type.get_bits(), 24U);
}

TEST(CustomNumericType, DeserialiseLittleEndianUnsignedOddSize)
{
	EXPECT_THROW({
		CustomNumericType type(AutoJSON("{ \"base-type\": \"UNSIGNED_INT\", \"endianness\": \"LITTLE\", \"bits\": 14 }").json);
	}, std::invalid_argument);
}

TEST(CustomNumericType, DeserialiseBigEndianUnsignedOddSize)
{
	CustomNumericType type(AutoJSON("{ \"base-type\": \"UNSIGNED_INT\", \"endianness\": \"BIG\", \"bits\": 14 }").json);
	
	EXPECT_EQ(type.get_base_type(), CustomNumericType::BaseType::UNSIGNED_INT);
	EXPECT_EQ(type.get_endianness(), CustomNumericType::Endianness::BIG);
	EXPECT_EQ(type.get_bits(), 14U);
}

TEST(CustomNumericType, DeserialiseLittleEndianSigned)
{
	CustomNumericType type(AutoJSON("{ \"base-type\": \"SIGNED_INT\", \"endianness\": \"LITTLE\", \"bits\": 24 }").json);
	
	EXPECT_EQ(type.get_base_type(), CustomNumericType::BaseType::SIGNED_INT);
	EXPECT_EQ(type.get_endianness(), CustomNumericType::Endianness::LITTLE);
	EXPECT_EQ(type.get_bits(), 24U);
}

TEST(CustomNumericType, DeserialiseInvalidBaseType)
{
	EXPECT_THROW({
		CustomNumericType type(AutoJSON("{ \"base-type\": \"STEVE\", \"endianness\": \"LITTLE\", \"bits\": 24 }").json);
	}, std::invalid_argument);
	
	EXPECT_THROW({
		CustomNumericType type(AutoJSON("{ \"base-type\": [], \"endianness\": \"LITTLE\", \"bits\": 24 }").json);
	}, std::invalid_argument);
	
	EXPECT_THROW({
		CustomNumericType type(AutoJSON("{ \"endianness\": \"LITTLE\", \"bits\": 24 }").json);
	}, std::invalid_argument);
}

TEST(CustomNumericType, DeserialiseInvalidEndian)
{
	EXPECT_THROW({
		CustomNumericType type(AutoJSON("{ \"base-type\": \"UNSIGNED_INT\", \"endianness\": \"LITTLE2\", \"bits\": 24 }").json);
	}, std::invalid_argument);
	
	EXPECT_THROW({
		CustomNumericType type(AutoJSON("{ \"base-type\": \"UNSIGNED_INT\", \"endianness\": [], \"bits\": 24 }").json);
	}, std::invalid_argument);
	
	EXPECT_THROW({
		CustomNumericType type(AutoJSON("{ \"base-type\": \"UNSIGNED_INT\", \"bits\": 24 }").json);
	}, std::invalid_argument);
}

TEST(CustomNumericType, DeserialiseInvalidBits)
{
	EXPECT_THROW({
		CustomNumericType type(AutoJSON("{ \"base-type\": \"UNSIGNED_INT\", \"endianness\": \"BIG\", \"bits\": 0 }").json);
	}, std::invalid_argument);
	
	EXPECT_THROW({
		CustomNumericType type(AutoJSON("{ \"base-type\": \"UNSIGNED_INT\", \"endianness\": \"BIG\", \"bits\": 65 }").json);
	}, std::invalid_argument);
	
	EXPECT_THROW({
		CustomNumericType type(AutoJSON("{ \"base-type\": \"UNSIGNED_INT\", \"endianness\": \"BIG\", \"bits\": [] }").json);
	}, std::invalid_argument);
	
	EXPECT_THROW({
		CustomNumericType type(AutoJSON("{ \"base-type\": \"UNSIGNED_INT\", \"endianness\": \"BIG\" }").json);
	}, std::invalid_argument);
}
