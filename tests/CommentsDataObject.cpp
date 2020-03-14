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

#include <gtest/gtest.h>
#include <iterator>

#include "../src/document.hpp"

using namespace REHex;

TEST(CommentsDataObject, SingleComment)
{
	NestedOffsetLengthMap<Document::Comment> expect_comments;
	NestedOffsetLengthMap_set(expect_comments, 1234567890, 1234567890, Document::Comment("yarn"));
	
	std::list<NestedOffsetLengthMap<Document::Comment>::const_iterator> in_comments;
	in_comments.push_back(expect_comments.begin());
	
	CommentsDataObject cdo_ser(in_comments);
	
	CommentsDataObject cdo_deser;
	cdo_deser.SetData(cdo_ser.GetSize(), cdo_ser.GetData());
	
	auto got_comments = cdo_deser.get_comments();
	
	EXPECT_EQ(got_comments, expect_comments) << "Single comment is correctly serialised/deserialised";
}

TEST(CommentsDataObject, MultipleComments)
{
	NestedOffsetLengthMap<Document::Comment> expect_comments;
	NestedOffsetLengthMap_set(expect_comments, 1234567890, 0, Document::Comment("simple"));
	NestedOffsetLengthMap_set(expect_comments, 1234567891, 0, Document::Comment("vivacious"));
	NestedOffsetLengthMap_set(expect_comments, 1234567892, 0, Document::Comment("fruit"));
	NestedOffsetLengthMap_set(expect_comments, 1234567893, 0, Document::Comment("cut"));
	NestedOffsetLengthMap_set(expect_comments, 1234567894, 0, Document::Comment("weak"));
	
	std::list<NestedOffsetLengthMap<Document::Comment>::const_iterator> in_comments;
	in_comments.push_back(std::next(expect_comments.begin(), 0));
	in_comments.push_back(std::next(expect_comments.begin(), 1));
	in_comments.push_back(std::next(expect_comments.begin(), 2));
	in_comments.push_back(std::next(expect_comments.begin(), 3));
	in_comments.push_back(std::next(expect_comments.begin(), 4));
	
	CommentsDataObject cdo_ser(in_comments);
	
	CommentsDataObject cdo_deser;
	cdo_deser.SetData(cdo_ser.GetSize(), cdo_ser.GetData());
	
	auto got_comments = cdo_deser.get_comments();
	
	EXPECT_EQ(got_comments, expect_comments) << "Multiple comments are correctly serialised/deserialised";
}

TEST(CommentsDataObject, ShiftOffset)
{
	NestedOffsetLengthMap<Document::Comment> source_comments;
	NestedOffsetLengthMap_set(source_comments, 1234567890, 0, Document::Comment("enter"));
	NestedOffsetLengthMap_set(source_comments, 1234567891, 0, Document::Comment("ludicrous"));
	NestedOffsetLengthMap_set(source_comments, 1234567892, 0, Document::Comment("acceptable"));
	NestedOffsetLengthMap_set(source_comments, 1234567893, 0, Document::Comment("discreet"));
	NestedOffsetLengthMap_set(source_comments, 1234567894, 0, Document::Comment("shocking"));
	
	std::list<NestedOffsetLengthMap<Document::Comment>::const_iterator> in_comments;
	in_comments.push_back(std::next(source_comments.begin(), 0));
	in_comments.push_back(std::next(source_comments.begin(), 1));
	in_comments.push_back(std::next(source_comments.begin(), 2));
	in_comments.push_back(std::next(source_comments.begin(), 3));
	in_comments.push_back(std::next(source_comments.begin(), 4));
	
	CommentsDataObject cdo_ser(in_comments, 10);
	
	CommentsDataObject cdo_deser;
	cdo_deser.SetData(cdo_ser.GetSize(), cdo_ser.GetData());
	
	auto got_comments = cdo_deser.get_comments();
	
	NestedOffsetLengthMap<Document::Comment> expect_comments;
	NestedOffsetLengthMap_set(expect_comments, 1234567880, 0, Document::Comment("enter"));
	NestedOffsetLengthMap_set(expect_comments, 1234567881, 0, Document::Comment("ludicrous"));
	NestedOffsetLengthMap_set(expect_comments, 1234567882, 0, Document::Comment("acceptable"));
	NestedOffsetLengthMap_set(expect_comments, 1234567883, 0, Document::Comment("discreet"));
	NestedOffsetLengthMap_set(expect_comments, 1234567884, 0, Document::Comment("shocking"));
	
	EXPECT_EQ(got_comments, expect_comments) << "Comment offsets are shifted by base";
}

TEST(CommentsDataObject, HighBitCharacters)
{
	NestedOffsetLengthMap<Document::Comment> expect_comments;
	NestedOffsetLengthMap_set(expect_comments, 1234567890, 0, Document::Comment(wxString::FromUTF8("\u0111\u00F0\u201D\u0127\u0167\u00DF\u201D\u014B\u00BB\u00B6\u2190\u00A2\u00FE\u03A9"))); /* đð”ħŧß”ŋ»¶←¢þΩ */
	NestedOffsetLengthMap_set(expect_comments, 1234567891, 0, Document::Comment(wxString::FromUTF8("\u2500\u00B2\u00F0\u00A2\u201C\u00AB\u262D\u00A7\u00D0\u00AA\u014A\u2019\u2018\u00A1"))); /* ─²ð¢“«☭§ÐªŊ’‘¡ */
	
	std::list<NestedOffsetLengthMap<Document::Comment>::const_iterator> in_comments;
	in_comments.push_back(std::next(expect_comments.begin(), 0));
	in_comments.push_back(std::next(expect_comments.begin(), 1));
	
	CommentsDataObject cdo_ser(in_comments);
	
	CommentsDataObject cdo_deser;
	cdo_deser.SetData(cdo_ser.GetSize(), cdo_ser.GetData());
	
	auto got_comments = cdo_deser.get_comments();
	
	EXPECT_EQ(got_comments, expect_comments) << "8 bit characters are preserved";
}
