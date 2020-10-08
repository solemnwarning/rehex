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

#include "../src/platform.hpp"

#include <gtest/gtest.h>
#include <list>
#include <stdexcept>
#include <vector>

#include "../src/document.hpp"
#include "../src/SharedDocumentPointer.hpp"
#include "../src/Tab.hpp"

using namespace REHex;

static std::vector<std::string> stringify_regions(const std::list<DocumentCtrl::Region*> &regions)
{
	std::vector<std::string> s_regions;
	
	for(auto r = regions.begin(); r != regions.end(); ++r)
	{
		char buf[128];
		
		DocumentCtrl::CommentRegion          *cr   = dynamic_cast<DocumentCtrl::CommentRegion*>(*r);
		DocumentCtrl::DataRegionDocHighlight *drdh = dynamic_cast<DocumentCtrl::DataRegionDocHighlight*>(*r);
		
		if(cr != NULL)
		{
			snprintf(buf, sizeof(buf),
				"CommentRegion(c_offset = %ld, c_length = %ld, indent_offset = %ld, indent_length = %ld, c_text = '%s', truncate = %d)",
				(long)(cr->c_offset), (long)(cr->c_length), (long)(cr->indent_offset), (long)(cr->indent_length), cr->c_text.ToStdString().c_str(), (int)(cr->truncate));
		}
		else if(drdh != NULL)
		{
			snprintf(buf, sizeof(buf),
				"DataRegionDocHighlight(d_offset = %ld, d_length = %ld, indent_offset = %ld, indent_length = %ld)",
				(long)(drdh->d_offset), (long)(drdh->d_length), (long)(drdh->indent_offset), (long)(drdh->indent_length));
		}
		else{
			throw std::runtime_error("Unknown Region subclass encountered");
		}
		
		s_regions.push_back(buf);
	}
	
	return s_regions;
}

static void free_regions(std::list<DocumentCtrl::Region*> &regions)
{
	for(auto r = regions.begin(); r != regions.end(); ++r)
	{
		delete (*r);
	}
	
	regions.clear();
}

TEST(Tab, ComputeRegionsEmptyFile)
{
	SharedDocumentPointer doc(SharedDocumentPointer::make());
	
	std::list<DocumentCtrl::Region*> regions = Tab::compute_regions(doc, ICM_HIDDEN);
	std::vector<std::string> s_regions = stringify_regions(regions);
	free_regions(regions);
	
	const std::vector<std::string> EXPECT_REGIONS = {
		"DataRegionDocHighlight(d_offset = 0, d_length = 0, indent_offset = 0, indent_length = 0)",
	};
	
	EXPECT_EQ(s_regions, EXPECT_REGIONS) << "REHex::Tab::compute_regions() returned correct regions";
}

TEST(Tab, ComputeRegionsNoComments)
{
	SharedDocumentPointer doc(SharedDocumentPointer::make());
	
	const std::vector<unsigned char> ZERO_4K(4096);
	doc->insert_data(0, ZERO_4K.data(), ZERO_4K.size());
	
	std::list<DocumentCtrl::Region*> regions = Tab::compute_regions(doc, ICM_FULL);
	std::vector<std::string> s_regions = stringify_regions(regions);
	free_regions(regions);
	
	const std::vector<std::string> EXPECT_REGIONS = {
		"DataRegionDocHighlight(d_offset = 0, d_length = 4096, indent_offset = 0, indent_length = 0)",
	};
	
	EXPECT_EQ(s_regions, EXPECT_REGIONS) << "REHex::Tab::compute_regions() returned correct regions";
}

TEST(Tab, ComputeRegionsFlatComments)
{
	SharedDocumentPointer doc(SharedDocumentPointer::make());
	
	const std::vector<unsigned char> ZERO_4K(4096);
	doc->insert_data(0, ZERO_4K.data(), ZERO_4K.size());
	
	doc->set_comment(1024, 128, REHex::Document::Comment("unite"));
	doc->set_comment(1024,   0, REHex::Document::Comment("robin"));
	doc->set_comment(1024,  64, REHex::Document::Comment("release"));
	doc->set_comment(1088,  64, REHex::Document::Comment("uncle"));
	doc->set_comment(1152,  64, REHex::Document::Comment("scarecrow"));
	doc->set_comment(2048,  64, REHex::Document::Comment("crowded"));
	
	std::list<DocumentCtrl::Region*> regions = Tab::compute_regions(doc, ICM_FULL);
	std::vector<std::string> s_regions = stringify_regions(regions);
	free_regions(regions);
	
	const std::vector<std::string> EXPECT_REGIONS = {
		"DataRegionDocHighlight(d_offset = 0, d_length = 1024, indent_offset = 0, indent_length = 0)",
		"CommentRegion(c_offset = 1024, c_length = 128, indent_offset = 1024, indent_length = 0, c_text = 'unite', truncate = 0)",
		"CommentRegion(c_offset = 1024, c_length = 64, indent_offset = 1024, indent_length = 0, c_text = 'release', truncate = 0)",
		"CommentRegion(c_offset = 1024, c_length = 0, indent_offset = 1024, indent_length = 0, c_text = 'robin', truncate = 0)",
		"DataRegionDocHighlight(d_offset = 1024, d_length = 64, indent_offset = 1024, indent_length = 0)",
		"CommentRegion(c_offset = 1088, c_length = 64, indent_offset = 1088, indent_length = 0, c_text = 'uncle', truncate = 0)",
		"DataRegionDocHighlight(d_offset = 1088, d_length = 64, indent_offset = 1088, indent_length = 0)",
		"CommentRegion(c_offset = 1152, c_length = 64, indent_offset = 1152, indent_length = 0, c_text = 'scarecrow', truncate = 0)",
		"DataRegionDocHighlight(d_offset = 1152, d_length = 896, indent_offset = 1152, indent_length = 0)",
		"CommentRegion(c_offset = 2048, c_length = 64, indent_offset = 2048, indent_length = 0, c_text = 'crowded', truncate = 0)",
		"DataRegionDocHighlight(d_offset = 2048, d_length = 2048, indent_offset = 2048, indent_length = 0)",
	};
	
	EXPECT_EQ(s_regions, EXPECT_REGIONS) << "REHex::Tab::compute_regions() returned correct regions";
}

TEST(Tab, ComputeRegionsShortComments)
{
	SharedDocumentPointer doc(SharedDocumentPointer::make());
	
	const std::vector<unsigned char> ZERO_4K(4096);
	doc->insert_data(0, ZERO_4K.data(), ZERO_4K.size());
	
	doc->set_comment(   0, 128, REHex::Document::Comment("unite"));
	doc->set_comment(   0,   0, REHex::Document::Comment("robin"));
	doc->set_comment(   0,  64, REHex::Document::Comment("release"));
	doc->set_comment(  64,  64, REHex::Document::Comment("uncle"));
	doc->set_comment( 128,  64, REHex::Document::Comment("scarecrow"));
	doc->set_comment(2048,  64, REHex::Document::Comment("crowded"));
	
	std::list<DocumentCtrl::Region*> regions = Tab::compute_regions(doc, ICM_SHORT);
	std::vector<std::string> s_regions = stringify_regions(regions);
	free_regions(regions);
	
	const std::vector<std::string> EXPECT_REGIONS = {
		"CommentRegion(c_offset = 0, c_length = 128, indent_offset = 0, indent_length = 0, c_text = 'unite', truncate = 1)",
		"CommentRegion(c_offset = 0, c_length = 64, indent_offset = 0, indent_length = 0, c_text = 'release', truncate = 1)",
		"CommentRegion(c_offset = 0, c_length = 0, indent_offset = 0, indent_length = 0, c_text = 'robin', truncate = 1)",
		"DataRegionDocHighlight(d_offset = 0, d_length = 64, indent_offset = 0, indent_length = 0)",
		"CommentRegion(c_offset = 64, c_length = 64, indent_offset = 64, indent_length = 0, c_text = 'uncle', truncate = 1)",
		"DataRegionDocHighlight(d_offset = 64, d_length = 64, indent_offset = 64, indent_length = 0)",
		"CommentRegion(c_offset = 128, c_length = 64, indent_offset = 128, indent_length = 0, c_text = 'scarecrow', truncate = 1)",
		"DataRegionDocHighlight(d_offset = 128, d_length = 1920, indent_offset = 128, indent_length = 0)",
		"CommentRegion(c_offset = 2048, c_length = 64, indent_offset = 2048, indent_length = 0, c_text = 'crowded', truncate = 1)",
		"DataRegionDocHighlight(d_offset = 2048, d_length = 2048, indent_offset = 2048, indent_length = 0)",
	};
	
	EXPECT_EQ(s_regions, EXPECT_REGIONS) << "REHex::Tab::compute_regions() returned correct regions";
}

TEST(Tab, ComputeRegionsHiddenComments)
{
	SharedDocumentPointer doc(SharedDocumentPointer::make());
	
	const std::vector<unsigned char> ZERO_4K(4096);
	doc->insert_data(0, ZERO_4K.data(), ZERO_4K.size());
	
	doc->set_comment(1024, 128, REHex::Document::Comment("unite"));
	
	std::list<DocumentCtrl::Region*> regions = Tab::compute_regions(doc, ICM_HIDDEN);
	std::vector<std::string> s_regions = stringify_regions(regions);
	free_regions(regions);
	
	const std::vector<std::string> EXPECT_REGIONS = {
		"DataRegionDocHighlight(d_offset = 0, d_length = 4096, indent_offset = 0, indent_length = 0)",
	};
	
	EXPECT_EQ(s_regions, EXPECT_REGIONS) << "REHex::Tab::compute_regions() returned correct regions";
}

TEST(Tab, ComputeRegionsNestedComments)
{
	SharedDocumentPointer doc(SharedDocumentPointer::make());
	
	const std::vector<unsigned char> ZERO_4K(4096);
	doc->insert_data(0, ZERO_4K.data(), ZERO_4K.size());
	
	doc->set_comment(1024,   128, REHex::Document::Comment("unite"));
	doc->set_comment(1024,     0, REHex::Document::Comment("robin"));
	doc->set_comment(1024,    64, REHex::Document::Comment("release"));
	doc->set_comment(1088,    64, REHex::Document::Comment("uncle"));
	doc->set_comment(1152,    64, REHex::Document::Comment("scarecrow"));
	doc->set_comment(2048,  2048, REHex::Document::Comment("crowded"));
	
	std::list<DocumentCtrl::Region*> regions = Tab::compute_regions(doc, ICM_FULL_INDENT);
	std::vector<std::string> s_regions = stringify_regions(regions);
	free_regions(regions);
	
	const std::vector<std::string> EXPECT_REGIONS = {
		"DataRegionDocHighlight(d_offset = 0, d_length = 1024, indent_offset = 0, indent_length = 0)",
		"CommentRegion(c_offset = 1024, c_length = 128, indent_offset = 1024, indent_length = 128, c_text = 'unite', truncate = 0)",
		"CommentRegion(c_offset = 1024, c_length = 64, indent_offset = 1024, indent_length = 64, c_text = 'release', truncate = 0)",
		"CommentRegion(c_offset = 1024, c_length = 0, indent_offset = 1024, indent_length = 0, c_text = 'robin', truncate = 0)",
		"DataRegionDocHighlight(d_offset = 1024, d_length = 64, indent_offset = 1024, indent_length = 0)",
		"CommentRegion(c_offset = 1088, c_length = 64, indent_offset = 1088, indent_length = 64, c_text = 'uncle', truncate = 0)",
		"DataRegionDocHighlight(d_offset = 1088, d_length = 64, indent_offset = 1088, indent_length = 0)",
		"CommentRegion(c_offset = 1152, c_length = 64, indent_offset = 1152, indent_length = 64, c_text = 'scarecrow', truncate = 0)",
		"DataRegionDocHighlight(d_offset = 1152, d_length = 64, indent_offset = 1152, indent_length = 0)",
		"DataRegionDocHighlight(d_offset = 1216, d_length = 832, indent_offset = 1216, indent_length = 0)",
		"CommentRegion(c_offset = 2048, c_length = 2048, indent_offset = 2048, indent_length = 2048, c_text = 'crowded', truncate = 0)",
		"DataRegionDocHighlight(d_offset = 2048, d_length = 2048, indent_offset = 2048, indent_length = 0)",
	};
	
	EXPECT_EQ(s_regions, EXPECT_REGIONS) << "REHex::Tab::compute_regions() returned correct regions";
}

TEST(Tab, ComputeRegionsNestedShortComments)
{
	SharedDocumentPointer doc(SharedDocumentPointer::make());
	
	const std::vector<unsigned char> ZERO_4K(4096);
	doc->insert_data(0, ZERO_4K.data(), ZERO_4K.size());
	
	doc->set_comment(1024, 128, REHex::Document::Comment("unite"));
	doc->set_comment(1024,   0, REHex::Document::Comment("robin"));
	doc->set_comment(1024,  64, REHex::Document::Comment("release"));
	doc->set_comment(1088,  64, REHex::Document::Comment("uncle"));
	doc->set_comment(1152,  64, REHex::Document::Comment("scarecrow"));
	doc->set_comment(2048,  64, REHex::Document::Comment("crowded"));
	
	std::list<DocumentCtrl::Region*> regions = Tab::compute_regions(doc, ICM_SHORT_INDENT);
	std::vector<std::string> s_regions = stringify_regions(regions);
	free_regions(regions);
	
	const std::vector<std::string> EXPECT_REGIONS = {
		"DataRegionDocHighlight(d_offset = 0, d_length = 1024, indent_offset = 0, indent_length = 0)",
		"CommentRegion(c_offset = 1024, c_length = 128, indent_offset = 1024, indent_length = 128, c_text = 'unite', truncate = 1)",
		"CommentRegion(c_offset = 1024, c_length = 64, indent_offset = 1024, indent_length = 64, c_text = 'release', truncate = 1)",
		"CommentRegion(c_offset = 1024, c_length = 0, indent_offset = 1024, indent_length = 0, c_text = 'robin', truncate = 1)",
		"DataRegionDocHighlight(d_offset = 1024, d_length = 64, indent_offset = 1024, indent_length = 0)",
		"CommentRegion(c_offset = 1088, c_length = 64, indent_offset = 1088, indent_length = 64, c_text = 'uncle', truncate = 1)",
		"DataRegionDocHighlight(d_offset = 1088, d_length = 64, indent_offset = 1088, indent_length = 0)",
		"CommentRegion(c_offset = 1152, c_length = 64, indent_offset = 1152, indent_length = 64, c_text = 'scarecrow', truncate = 1)",
		"DataRegionDocHighlight(d_offset = 1152, d_length = 64, indent_offset = 1152, indent_length = 0)",
		"DataRegionDocHighlight(d_offset = 1216, d_length = 832, indent_offset = 1216, indent_length = 0)",
		"CommentRegion(c_offset = 2048, c_length = 64, indent_offset = 2048, indent_length = 64, c_text = 'crowded', truncate = 1)",
		"DataRegionDocHighlight(d_offset = 2048, d_length = 64, indent_offset = 2048, indent_length = 0)",
		"DataRegionDocHighlight(d_offset = 2112, d_length = 1984, indent_offset = 2112, indent_length = 0)",
	};
	
	EXPECT_EQ(s_regions, EXPECT_REGIONS) << "REHex::Tab::compute_regions() returned correct regions";
}
