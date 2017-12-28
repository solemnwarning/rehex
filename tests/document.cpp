/* Reverse Engineer's Hex Editor
 * Copyright (C) 2017 Daniel Collins <solemnwarning@solemnwarning.net>
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

#undef NDEBUG
#include <assert.h>

#include <stdexcept>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wx/init.h>
#include <wx/wx.h>

#include "tests/tap/basic.h"

#define UNIT_TEST
#include "../src/document.hpp"

#define TEST_REGION_INT(region_i, type, field, expect) { \
	auto r = dynamic_cast<type*>(*(std::next(doc->regions.begin(), region_i))); \
	assert(r != NULL); \
	is_int(expect, r->field, "Document::regions[" #region_i "]." #field); \
}

#define TEST_REGION_STR(region_i, type, field, expect) { \
	auto r = dynamic_cast<type*>(*(std::next(doc->regions.begin(), region_i))); \
	assert(r != NULL); \
	is_string(expect, r->field.c_str(), "Document::regions[" #region_i "]." #field); \
}

static void insert_tests()
{
	{
		diag("Inserting into an empty file...");
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame, wxID_ANY, new REHex::Buffer());
		doc->SetSize(0,0, 640,480);
		
		unsigned char z4[] = {0x00,0x00,0x00,0x00};
		
		doc->regions.clear();
		doc->regions.push_back(new REHex::Document::Region::Data(0,0));
		doc->data_regions_count = 1;
		
		wxClientDC dc(doc);
		doc->_insert_data(dc, 0, z4, 4);
		
		is_int(4, doc->buffer->length(), "Document::_insert_data() expands Buffer")
			&& is_blob(z4, doc->buffer->read_data(0, 1024).data(), 4, "Document::_insert_data() inserts correct data into Buffer");
		
		assert(doc->regions.size() == 1);
		
		{
			auto dr = dynamic_cast<REHex::Document::Region::Data*>(*(doc->regions.begin()));
			assert(dr != NULL);
			
			is_int(0, dr->d_offset, "Document::regions[0].d_offset");
			is_int(4, dr->d_length, "Document::regions[0].d_length");
		}
	}
	
	{
		diag("Prepending to a file with a single data region");
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame, wxID_ANY, new REHex::Buffer());
		doc->SetSize(0,0, 640,480);
		
		unsigned char z4[]   = {0x00,0x00,0x00,0x00};
		unsigned char f2[]   = {0xFF,0xFF};
		unsigned char f2z4[] = {0xFF,0xFF,0x00,0x00,0x00,0x00};
		
		doc->buffer->insert_data(0, z4, 4);
		
		doc->regions.clear();
		doc->regions.push_back(new REHex::Document::Region::Data(0,4));
		doc->data_regions_count = 1;
		
		wxClientDC dc(doc);
		doc->_insert_data(dc, 0, f2, 2);
		
		is_int(6, doc->buffer->length(), "Document::_insert_data() expands Buffer")
			&& is_blob(f2z4, doc->buffer->read_data(0, 1024).data(), 6, "Document::_insert_data() inserts correct data into Buffer");
		
		assert(doc->regions.size() == 1);
		
		{
			auto dr = dynamic_cast<REHex::Document::Region::Data*>(*(doc->regions.begin()));
			assert(dr != NULL);
			
			is_int(0, dr->d_offset, "Document::regions[0].d_offset");
			is_int(6, dr->d_length, "Document::regions[0].d_length");
		}
	}
	
	{
		diag("Inserting into a file with a single data region");
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame, wxID_ANY, new REHex::Buffer());
		doc->SetSize(0,0, 640,480);
		
		unsigned char z4[]     = {0x00,0x00,0x00,0x00};
		unsigned char f2[]     = {0xFF,0xFF};
		unsigned char z2f2z2[] = {0x00,0x00,0xFF,0xFF,0x00,0x00};
		
		doc->buffer->insert_data(0, z4, 4);
		
		doc->regions.clear();
		doc->regions.push_back(new REHex::Document::Region::Data(0,4));
		doc->data_regions_count = 1;
		
		wxClientDC dc(doc);
		doc->_insert_data(dc, 2, f2, 2);
		
		is_int(6, doc->buffer->length(), "Document::_insert_data() expands Buffer")
			&& is_blob(z2f2z2, doc->buffer->read_data(0, 1024).data(), 6, "Document::_insert_data() inserts correct data into Buffer");
		
		assert(doc->regions.size() == 1);
		
		{
			auto dr = dynamic_cast<REHex::Document::Region::Data*>(*(doc->regions.begin()));
			assert(dr != NULL);
			
			is_int(0, dr->d_offset, "Document::regions[0].d_offset");
			is_int(6, dr->d_length, "Document::regions[0].d_length");
		}
	}
	
	{
		diag("Appending to a file with a single data region");
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame, wxID_ANY, new REHex::Buffer());
		doc->SetSize(0,0, 640,480);
		
		unsigned char z4[]   = {0x00,0x00,0x00,0x00};
		unsigned char f2[]   = {0xFF,0xFF};
		unsigned char z4f2[] = {0x00,0x00,0x00,0x00,0xFF,0xFF};
		
		doc->buffer->insert_data(0, z4, 4);
		
		doc->regions.clear();
		doc->regions.push_back(new REHex::Document::Region::Data(0,4));
		doc->data_regions_count = 1;
		
		wxClientDC dc(doc);
		doc->_insert_data(dc, 4, f2, 2);
		
		is_int(6, doc->buffer->length(), "Document::_insert_data() expands Buffer")
			&& is_blob(z4f2, doc->buffer->read_data(0, 1024).data(), 6, "Document::_insert_data() inserts correct data into Buffer");
		
		assert(doc->regions.size() == 1);
		
		{
			auto dr = dynamic_cast<REHex::Document::Region::Data*>(*(doc->regions.begin()));
			assert(dr != NULL);
			
			is_int(0, dr->d_offset, "Document::regions[0].d_offset");
			is_int(6, dr->d_length, "Document::regions[0].d_length");
		}
	}
	
	{
		diag("Prepending to data region 1/3 in a Document");
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame, wxID_ANY, new REHex::Buffer());
		doc->SetSize(0,0, 640,480);
		
		unsigned char buffer_initial[] = {0x00,0x00,0x00,0x01,0x01,0x01,0x01,0x02,0x02};
		unsigned char to_insert[]      = {0xFF,0xFF};
		unsigned char buffer_final[]   = {0xFF,0xFF,0x00,0x00,0x00,0x01,0x01,0x01,0x01,0x02,0x02};
		
		doc->buffer->insert_data(0, buffer_initial, sizeof(buffer_initial));
		
		doc->regions.clear();
		doc->regions.push_back(new REHex::Document::Region::Comment(0,"a"));
		doc->regions.push_back(new REHex::Document::Region::Data(0,3));
		doc->regions.push_back(new REHex::Document::Region::Comment(3,"b"));
		doc->regions.push_back(new REHex::Document::Region::Data(3,4));
		doc->regions.push_back(new REHex::Document::Region::Comment(7,"c"));
		doc->regions.push_back(new REHex::Document::Region::Data(7,2));
		doc->data_regions_count = 3;
		
		wxClientDC dc(doc);
		doc->_insert_data(dc, 0, to_insert, sizeof(to_insert));
		
		is_int(sizeof(buffer_final), doc->buffer->length(), "Document::_insert_data() expands Buffer")
			&& is_blob(buffer_final, doc->buffer->read_data(0, 1024).data(), sizeof(buffer_final), "Document::_insert_data() inserts correct data into Buffer");
		
		assert(doc->regions.size() == 6);
		
		TEST_REGION_INT(0, REHex::Document::Region::Comment, d_offset, 0);
		TEST_REGION_STR(0, REHex::Document::Region::Comment, text,     "a");
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_offset, 0);
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_length, 5);
		
		TEST_REGION_INT(2, REHex::Document::Region::Comment, d_offset, 5);
		TEST_REGION_STR(2, REHex::Document::Region::Comment, text,     "b");
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_offset, 5);
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_length, 4);
		
		TEST_REGION_INT(4, REHex::Document::Region::Comment, d_offset, 9);
		TEST_REGION_STR(4, REHex::Document::Region::Comment, text,     "c");
		TEST_REGION_INT(5, REHex::Document::Region::Data,    d_offset, 9);
		TEST_REGION_INT(5, REHex::Document::Region::Data,    d_length, 2);
	}
	
	{
		diag("Inserting into data region 1/3 in a Document");
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame, wxID_ANY, new REHex::Buffer());
		doc->SetSize(0,0, 640,480);
		
		unsigned char buffer_initial[] = {0x00,0x00,0x00,0x01,0x01,0x01,0x01,0x02,0x02};
		unsigned char to_insert[]      = {0xFF,0xFF};
		unsigned char buffer_final[]   = {0x00,0x00,0xFF,0xFF,0x00,0x01,0x01,0x01,0x01,0x02,0x02};
		
		doc->buffer->insert_data(0, buffer_initial, sizeof(buffer_initial));
		
		doc->regions.clear();
		doc->regions.push_back(new REHex::Document::Region::Comment(0,"a"));
		doc->regions.push_back(new REHex::Document::Region::Data(0,3));
		doc->regions.push_back(new REHex::Document::Region::Comment(3,"b"));
		doc->regions.push_back(new REHex::Document::Region::Data(3,4));
		doc->regions.push_back(new REHex::Document::Region::Comment(7,"c"));
		doc->regions.push_back(new REHex::Document::Region::Data(7,2));
		doc->data_regions_count = 3;
		
		wxClientDC dc(doc);
		doc->_insert_data(dc, 2, to_insert, sizeof(to_insert));
		
		is_int(sizeof(buffer_final), doc->buffer->length(), "Document::_insert_data() expands Buffer")
			&& is_blob(buffer_final, doc->buffer->read_data(0, 1024).data(), sizeof(buffer_final), "Document::_insert_data() inserts correct data into Buffer");
		
		assert(doc->regions.size() == 6);
		
		TEST_REGION_INT(0, REHex::Document::Region::Comment, d_offset, 0);
		TEST_REGION_STR(0, REHex::Document::Region::Comment, text,     "a");
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_offset, 0);
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_length, 5);
		
		TEST_REGION_INT(2, REHex::Document::Region::Comment, d_offset, 5);
		TEST_REGION_STR(2, REHex::Document::Region::Comment, text,     "b");
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_offset, 5);
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_length, 4);
		
		TEST_REGION_INT(4, REHex::Document::Region::Comment, d_offset, 9);
		TEST_REGION_STR(4, REHex::Document::Region::Comment, text,     "c");
		TEST_REGION_INT(5, REHex::Document::Region::Data,    d_offset, 9);
		TEST_REGION_INT(5, REHex::Document::Region::Data,    d_length, 2);
	}
	
	{
		diag("Prepending to data region 2/3 in a Document");
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame, wxID_ANY, new REHex::Buffer());
		doc->SetSize(0,0, 640,480);
		
		unsigned char buffer_initial[] = {0x00,0x00,0x00,0x01,0x01,0x01,0x01,0x02,0x02};
		unsigned char to_insert[]      = {0xFF,0xFF};
		unsigned char buffer_final[]   = {0x00,0x00,0x00,0xFF,0xFF,0x01,0x01,0x01,0x01,0x02,0x02};
		
		doc->buffer->insert_data(0, buffer_initial, sizeof(buffer_initial));
		
		doc->regions.clear();
		doc->regions.push_back(new REHex::Document::Region::Comment(0,"a"));
		doc->regions.push_back(new REHex::Document::Region::Data(0,3));
		doc->regions.push_back(new REHex::Document::Region::Comment(3,"b"));
		doc->regions.push_back(new REHex::Document::Region::Data(3,4));
		doc->regions.push_back(new REHex::Document::Region::Comment(7,"c"));
		doc->regions.push_back(new REHex::Document::Region::Data(7,2));
		doc->data_regions_count = 3;
		
		wxClientDC dc(doc);
		doc->_insert_data(dc, 3, to_insert, sizeof(to_insert));
		
		is_int(sizeof(buffer_final), doc->buffer->length(), "Document::_insert_data() expands Buffer")
			&& is_blob(buffer_final, doc->buffer->read_data(0, 1024).data(), sizeof(buffer_final), "Document::_insert_data() inserts correct data into Buffer");
		
		assert(doc->regions.size() == 6);
		
		TEST_REGION_INT(0, REHex::Document::Region::Comment, d_offset, 0);
		TEST_REGION_STR(0, REHex::Document::Region::Comment, text,     "a");
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_offset, 0);
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_length, 3);
		
		TEST_REGION_INT(2, REHex::Document::Region::Comment, d_offset, 3);
		TEST_REGION_STR(2, REHex::Document::Region::Comment, text,     "b");
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_offset, 3);
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_length, 6);
		
		TEST_REGION_INT(4, REHex::Document::Region::Comment, d_offset, 9);
		TEST_REGION_STR(4, REHex::Document::Region::Comment, text,     "c");
		TEST_REGION_INT(5, REHex::Document::Region::Data,    d_offset, 9);
		TEST_REGION_INT(5, REHex::Document::Region::Data,    d_length, 2);
	}
	
	{
		diag("Inserting into data region 2/3 in a Document");
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame, wxID_ANY, new REHex::Buffer());
		doc->SetSize(0,0, 640,480);
		
		unsigned char buffer_initial[] = {0x00,0x00,0x00,0x01,0x01,0x01,0x01,0x02,0x02};
		unsigned char to_insert[]      = {0xFF,0xFF};
		unsigned char buffer_final[]   = {0x00,0x00,0x00,0x01,0x01,0x01,0xFF,0xFF,0x01,0x02,0x02};
		
		doc->buffer->insert_data(0, buffer_initial, sizeof(buffer_initial));
		
		doc->regions.clear();
		doc->regions.push_back(new REHex::Document::Region::Comment(0,"a"));
		doc->regions.push_back(new REHex::Document::Region::Data(0,3));
		doc->regions.push_back(new REHex::Document::Region::Comment(3,"b"));
		doc->regions.push_back(new REHex::Document::Region::Data(3,4));
		doc->regions.push_back(new REHex::Document::Region::Comment(7,"c"));
		doc->regions.push_back(new REHex::Document::Region::Data(7,2));
		doc->data_regions_count = 3;
		
		wxClientDC dc(doc);
		doc->_insert_data(dc, 6, to_insert, sizeof(to_insert));
		
		is_int(sizeof(buffer_final), doc->buffer->length(), "Document::_insert_data() expands Buffer")
			&& is_blob(buffer_final, doc->buffer->read_data(0, 1024).data(), sizeof(buffer_final), "Document::_insert_data() inserts correct data into Buffer");
		
		assert(doc->regions.size() == 6);
		
		TEST_REGION_INT(0, REHex::Document::Region::Comment, d_offset, 0);
		TEST_REGION_STR(0, REHex::Document::Region::Comment, text,     "a");
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_offset, 0);
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_length, 3);
		
		TEST_REGION_INT(2, REHex::Document::Region::Comment, d_offset, 3);
		TEST_REGION_STR(2, REHex::Document::Region::Comment, text,     "b");
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_offset, 3);
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_length, 6);
		
		TEST_REGION_INT(4, REHex::Document::Region::Comment, d_offset, 9);
		TEST_REGION_STR(4, REHex::Document::Region::Comment, text,     "c");
		TEST_REGION_INT(5, REHex::Document::Region::Data,    d_offset, 9);
		TEST_REGION_INT(5, REHex::Document::Region::Data,    d_length, 2);
	}
	
	{
		diag("Prepending to data region 3/3 in a Document");
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame, wxID_ANY, new REHex::Buffer());
		doc->SetSize(0,0, 640,480);
		
		unsigned char buffer_initial[] = {0x00,0x00,0x00,0x01,0x01,0x01,0x01,0x02,0x02};
		unsigned char to_insert[]      = {0xFF,0xFF};
		unsigned char buffer_final[]   = {0x00,0x00,0x00,0x01,0x01,0x01,0x01,0xFF,0xFF,0x02,0x02};
		
		doc->buffer->insert_data(0, buffer_initial, sizeof(buffer_initial));
		
		doc->regions.clear();
		doc->regions.push_back(new REHex::Document::Region::Comment(0,"a"));
		doc->regions.push_back(new REHex::Document::Region::Data(0,3));
		doc->regions.push_back(new REHex::Document::Region::Comment(3,"b"));
		doc->regions.push_back(new REHex::Document::Region::Data(3,4));
		doc->regions.push_back(new REHex::Document::Region::Comment(7,"c"));
		doc->regions.push_back(new REHex::Document::Region::Data(7,2));
		doc->data_regions_count = 3;
		
		wxClientDC dc(doc);
		doc->_insert_data(dc, 7, to_insert, sizeof(to_insert));
		
		is_int(sizeof(buffer_final), doc->buffer->length(), "Document::_insert_data() expands Buffer")
			&& is_blob(buffer_final, doc->buffer->read_data(0, 1024).data(), sizeof(buffer_final), "Document::_insert_data() inserts correct data into Buffer");
		
		assert(doc->regions.size() == 6);
		
		TEST_REGION_INT(0, REHex::Document::Region::Comment, d_offset, 0);
		TEST_REGION_STR(0, REHex::Document::Region::Comment, text,     "a");
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_offset, 0);
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_length, 3);
		
		TEST_REGION_INT(2, REHex::Document::Region::Comment, d_offset, 3);
		TEST_REGION_STR(2, REHex::Document::Region::Comment, text,     "b");
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_offset, 3);
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_length, 4);
		
		TEST_REGION_INT(4, REHex::Document::Region::Comment, d_offset, 7);
		TEST_REGION_STR(4, REHex::Document::Region::Comment, text,     "c");
		TEST_REGION_INT(5, REHex::Document::Region::Data,    d_offset, 7);
		TEST_REGION_INT(5, REHex::Document::Region::Data,    d_length, 4);
	}
	
	{
		diag("Inserting into data region 3/3 in a Document");
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame, wxID_ANY, new REHex::Buffer());
		doc->SetSize(0,0, 640,480);
		
		unsigned char buffer_initial[] = {0x00,0x00,0x00,0x01,0x01,0x01,0x01,0x02,0x02,0x02,0x02};
		unsigned char to_insert[]      = {0xFF,0xFF};
		unsigned char buffer_final[]   = {0x00,0x00,0x00,0x01,0x01,0x01,0x01,0x02,0xFF,0xFF,0x02,0x02,0x02};
		
		doc->buffer->insert_data(0, buffer_initial, sizeof(buffer_initial));
		
		doc->regions.clear();
		doc->regions.push_back(new REHex::Document::Region::Comment(0,"a"));
		doc->regions.push_back(new REHex::Document::Region::Data(0,3));
		doc->regions.push_back(new REHex::Document::Region::Comment(3,"b"));
		doc->regions.push_back(new REHex::Document::Region::Data(3,4));
		doc->regions.push_back(new REHex::Document::Region::Comment(7,"c"));
		doc->regions.push_back(new REHex::Document::Region::Data(7,4));
		doc->data_regions_count = 3;
		
		wxClientDC dc(doc);
		doc->_insert_data(dc, 8, to_insert, sizeof(to_insert));
		
		is_int(sizeof(buffer_final), doc->buffer->length(), "Document::_insert_data() expands Buffer")
			&& is_blob(buffer_final, doc->buffer->read_data(0, 1024).data(), sizeof(buffer_final), "Document::_insert_data() inserts correct data into Buffer");
		
		assert(doc->regions.size() == 6);
		
		TEST_REGION_INT(0, REHex::Document::Region::Comment, d_offset, 0);
		TEST_REGION_STR(0, REHex::Document::Region::Comment, text,     "a");
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_offset, 0);
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_length, 3);
		
		TEST_REGION_INT(2, REHex::Document::Region::Comment, d_offset, 3);
		TEST_REGION_STR(2, REHex::Document::Region::Comment, text,     "b");
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_offset, 3);
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_length, 4);
		
		TEST_REGION_INT(4, REHex::Document::Region::Comment, d_offset, 7);
		TEST_REGION_STR(4, REHex::Document::Region::Comment, text,     "c");
		TEST_REGION_INT(5, REHex::Document::Region::Data,    d_offset, 7);
		TEST_REGION_INT(5, REHex::Document::Region::Data,    d_length, 6);
	}
	
	{
		diag("Appending to data region 3/3 in a Document");
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame, wxID_ANY, new REHex::Buffer());
		doc->SetSize(0,0, 640,480);
		
		unsigned char buffer_initial[] = {0x00,0x00,0x00,0x01,0x01,0x01,0x01,0x02,0x02};
		unsigned char to_insert[]      = {0xFF,0xFF};
		unsigned char buffer_final[]   = {0x00,0x00,0x00,0x01,0x01,0x01,0x01,0x02,0x02,0xFF,0xFF};
		
		doc->buffer->insert_data(0, buffer_initial, sizeof(buffer_initial));
		
		doc->regions.clear();
		doc->regions.push_back(new REHex::Document::Region::Comment(0,"a"));
		doc->regions.push_back(new REHex::Document::Region::Data(0,3));
		doc->regions.push_back(new REHex::Document::Region::Comment(3,"b"));
		doc->regions.push_back(new REHex::Document::Region::Data(3,4));
		doc->regions.push_back(new REHex::Document::Region::Comment(7,"c"));
		doc->regions.push_back(new REHex::Document::Region::Data(7,2));
		doc->data_regions_count = 3;
		
		wxClientDC dc(doc);
		doc->_insert_data(dc, 9, to_insert, sizeof(to_insert));
		
		is_int(sizeof(buffer_final), doc->buffer->length(), "Document::_insert_data() expands Buffer")
			&& is_blob(buffer_final, doc->buffer->read_data(0, 1024).data(), sizeof(buffer_final), "Document::_insert_data() inserts correct data into Buffer");
		
		assert(doc->regions.size() == 6);
		
		TEST_REGION_INT(0, REHex::Document::Region::Comment, d_offset, 0);
		TEST_REGION_STR(0, REHex::Document::Region::Comment, text,     "a");
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_offset, 0);
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_length, 3);
		
		TEST_REGION_INT(2, REHex::Document::Region::Comment, d_offset, 3);
		TEST_REGION_STR(2, REHex::Document::Region::Comment, text,     "b");
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_offset, 3);
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_length, 4);
		
		TEST_REGION_INT(4, REHex::Document::Region::Comment, d_offset, 7);
		TEST_REGION_STR(4, REHex::Document::Region::Comment, text,     "c");
		TEST_REGION_INT(5, REHex::Document::Region::Data,    d_offset, 7);
		TEST_REGION_INT(5, REHex::Document::Region::Data,    d_length, 4);
	}
	
	/* TODO: Check y_* values */
}

static void erase_tests()
{
	{
		diag("Erasing the start of a Document with a single data region");
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame, wxID_ANY, new REHex::Buffer());
		doc->SetSize(0,0, 640,480);
		
		unsigned char buffer_initial[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07};
		unsigned char buffer_final[]   = {0x03,0x04,0x05,0x06,0x07};
		
		doc->buffer->insert_data(0, buffer_initial, sizeof(buffer_initial));
		
		doc->regions.clear();
		doc->regions.push_back(new REHex::Document::Region::Data(0,8));
		doc->data_regions_count = 1;
		
		wxClientDC dc(doc);
		doc->_erase_data(dc, 0, 3);
		
		is_int(sizeof(buffer_final), doc->buffer->length(), "Document::_erase_data() shrinks Buffer")
			&& is_blob(buffer_final, doc->buffer->read_data(0, 1024).data(), sizeof(buffer_final), "Document::_erase_data() erases correct data from Buffer");
		
		assert(doc->regions.size() == 1);
		is_int(1, doc->data_regions_count, "Document::data_regions_count");
		
		TEST_REGION_INT(0, REHex::Document::Region::Data, d_offset, 0);
		TEST_REGION_INT(0, REHex::Document::Region::Data, d_length, 5);
	}
	
	{
		diag("Erasing the middle of a Document with a single data region");
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame, wxID_ANY, new REHex::Buffer());
		doc->SetSize(0,0, 640,480);
		
		unsigned char buffer_initial[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07};
		unsigned char buffer_final[]   = {0x00,0x01,0x03,0x04,0x05,0x06,0x07};
		
		doc->buffer->insert_data(0, buffer_initial, sizeof(buffer_initial));
		
		doc->regions.clear();
		doc->regions.push_back(new REHex::Document::Region::Data(0,8));
		doc->data_regions_count = 1;
		
		wxClientDC dc(doc);
		doc->_erase_data(dc, 2, 1);
		
		is_int(sizeof(buffer_final), doc->buffer->length(), "Document::_erase_data() shrinks Buffer")
			&& is_blob(buffer_final, doc->buffer->read_data(0, 1024).data(), sizeof(buffer_final), "Document::_erase_data() erases correct data from Buffer");
		
		assert(doc->regions.size() == 1);
		is_int(1, doc->data_regions_count, "Document::data_regions_count");
		
		TEST_REGION_INT(0, REHex::Document::Region::Data, d_offset, 0);
		TEST_REGION_INT(0, REHex::Document::Region::Data, d_length, 7);
	}
	
	{
		diag("Erasing the end of a Document with a single data region");
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame, wxID_ANY, new REHex::Buffer());
		doc->SetSize(0,0, 640,480);
		
		unsigned char buffer_initial[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07};
		unsigned char buffer_final[]   = {0x00,0x01,0x02,0x03,0x04,0x05};
		
		doc->buffer->insert_data(0, buffer_initial, sizeof(buffer_initial));
		
		doc->regions.clear();
		doc->regions.push_back(new REHex::Document::Region::Data(0,8));
		doc->data_regions_count = 1;
		
		wxClientDC dc(doc);
		doc->_erase_data(dc, 6, 2);
		
		is_int(sizeof(buffer_final), doc->buffer->length(), "Document::_erase_data() shrinks Buffer")
			&& is_blob(buffer_final, doc->buffer->read_data(0, 1024).data(), sizeof(buffer_final), "Document::_erase_data() erases correct data from Buffer");
		
		assert(doc->regions.size() == 1);
		is_int(1, doc->data_regions_count, "Document::data_regions_count");
		
		TEST_REGION_INT(0, REHex::Document::Region::Data, d_offset, 0);
		TEST_REGION_INT(0, REHex::Document::Region::Data, d_length, 6);
	}
	
	{
		diag("Erasing all of a Document with a single data region");
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame, wxID_ANY, new REHex::Buffer());
		doc->SetSize(0,0, 640,480);
		
		unsigned char buffer_initial[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07};
		unsigned char buffer_final[]   = {};
		
		doc->buffer->insert_data(0, buffer_initial, sizeof(buffer_initial));
		
		doc->regions.clear();
		doc->regions.push_back(new REHex::Document::Region::Data(0,8));
		doc->data_regions_count = 1;
		
		wxClientDC dc(doc);
		doc->_erase_data(dc, 0, 8);
		
		is_int(sizeof(buffer_final), doc->buffer->length(), "Document::_erase_data() shrinks Buffer")
			&& is_blob(buffer_final, doc->buffer->read_data(0, 1024).data(), sizeof(buffer_final), "Document::_erase_data() erases correct data from Buffer");
		
		assert(doc->regions.size() == 1);
		is_int(1, doc->data_regions_count, "Document::data_regions_count");
		
		TEST_REGION_INT(0, REHex::Document::Region::Data, d_offset, 0);
		TEST_REGION_INT(0, REHex::Document::Region::Data, d_length, 0);
	}
	
	{
		diag("Erasing the start of data region 1/3 in a Document");
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame, wxID_ANY, new REHex::Buffer());
		doc->SetSize(0,0, 640,480);
		
		unsigned char buffer_initial[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C};
		unsigned char buffer_final[]   = {0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C};
		
		doc->buffer->insert_data(0, buffer_initial, sizeof(buffer_initial));
		
		doc->regions.clear();
		doc->regions.push_back(new REHex::Document::Region::Comment(0,"a"));
		doc->regions.push_back(new REHex::Document::Region::Data(0,5));
		doc->regions.push_back(new REHex::Document::Region::Comment(5,"b"));
		doc->regions.push_back(new REHex::Document::Region::Data(5,4));
		doc->regions.push_back(new REHex::Document::Region::Comment(9,"c"));
		doc->regions.push_back(new REHex::Document::Region::Data(9,4));
		doc->data_regions_count = 3;
		
		wxClientDC dc(doc);
		doc->_erase_data(dc, 0, 2);
		
		is_int(sizeof(buffer_final), doc->buffer->length(), "Document::_erase_data() shrinks Buffer")
			&& is_blob(buffer_final, doc->buffer->read_data(0, 1024).data(), sizeof(buffer_final), "Document::_erase_data() erases correct data from Buffer");
		
		assert(doc->regions.size() == 6);
		is_int(3, doc->data_regions_count, "Document::data_regions_count");
		
		TEST_REGION_INT(0, REHex::Document::Region::Comment, d_offset, 0);
		TEST_REGION_STR(0, REHex::Document::Region::Comment, text,     "a");
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_offset, 0);
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_length, 3);
		
		TEST_REGION_INT(2, REHex::Document::Region::Comment, d_offset, 3);
		TEST_REGION_STR(2, REHex::Document::Region::Comment, text,     "b");
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_offset, 3);
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_length, 4);
		
		TEST_REGION_INT(4, REHex::Document::Region::Comment, d_offset, 7);
		TEST_REGION_STR(4, REHex::Document::Region::Comment, text,     "c");
		TEST_REGION_INT(5, REHex::Document::Region::Data,    d_offset, 7);
		TEST_REGION_INT(5, REHex::Document::Region::Data,    d_length, 4);
	}
	
	{
		diag("Erasing the middle of data region 1/3 in a Document");
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame, wxID_ANY, new REHex::Buffer());
		doc->SetSize(0,0, 640,480);
		
		unsigned char buffer_initial[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C};
		unsigned char buffer_final[]   = {0x00,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C};
		
		doc->buffer->insert_data(0, buffer_initial, sizeof(buffer_initial));
		
		doc->regions.clear();
		doc->regions.push_back(new REHex::Document::Region::Comment(0,"a"));
		doc->regions.push_back(new REHex::Document::Region::Data(0,5));
		doc->regions.push_back(new REHex::Document::Region::Comment(5,"b"));
		doc->regions.push_back(new REHex::Document::Region::Data(5,4));
		doc->regions.push_back(new REHex::Document::Region::Comment(9,"c"));
		doc->regions.push_back(new REHex::Document::Region::Data(9,4));
		doc->data_regions_count = 3;
		
		wxClientDC dc(doc);
		doc->_erase_data(dc, 1, 3);
		
		is_int(sizeof(buffer_final), doc->buffer->length(), "Document::_erase_data() shrinks Buffer")
			&& is_blob(buffer_final, doc->buffer->read_data(0, 1024).data(), sizeof(buffer_final), "Document::_erase_data() erases correct data from Buffer");
		
		assert(doc->regions.size() == 6);
		is_int(3, doc->data_regions_count, "Document::data_regions_count");
		
		TEST_REGION_INT(0, REHex::Document::Region::Comment, d_offset, 0);
		TEST_REGION_STR(0, REHex::Document::Region::Comment, text,     "a");
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_offset, 0);
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_length, 2);
		
		TEST_REGION_INT(2, REHex::Document::Region::Comment, d_offset, 2);
		TEST_REGION_STR(2, REHex::Document::Region::Comment, text,     "b");
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_offset, 2);
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_length, 4);
		
		TEST_REGION_INT(4, REHex::Document::Region::Comment, d_offset, 6);
		TEST_REGION_STR(4, REHex::Document::Region::Comment, text,     "c");
		TEST_REGION_INT(5, REHex::Document::Region::Data,    d_offset, 6);
		TEST_REGION_INT(5, REHex::Document::Region::Data,    d_length, 4);
	}
	
	{
		diag("Erasing the end of data region 1/3 in a Document");
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame, wxID_ANY, new REHex::Buffer());
		doc->SetSize(0,0, 640,480);
		
		unsigned char buffer_initial[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C};
		unsigned char buffer_final[]   = {0x00,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C};
		
		doc->buffer->insert_data(0, buffer_initial, sizeof(buffer_initial));
		
		doc->regions.clear();
		doc->regions.push_back(new REHex::Document::Region::Comment(0,"a"));
		doc->regions.push_back(new REHex::Document::Region::Data(0,5));
		doc->regions.push_back(new REHex::Document::Region::Comment(5,"b"));
		doc->regions.push_back(new REHex::Document::Region::Data(5,4));
		doc->regions.push_back(new REHex::Document::Region::Comment(9,"c"));
		doc->regions.push_back(new REHex::Document::Region::Data(9,4));
		doc->data_regions_count = 3;
		
		wxClientDC dc(doc);
		doc->_erase_data(dc, 1, 4);
		
		is_int(sizeof(buffer_final), doc->buffer->length(), "Document::_erase_data() shrinks Buffer")
			&& is_blob(buffer_final, doc->buffer->read_data(0, 1024).data(), sizeof(buffer_final), "Document::_erase_data() erases correct data from Buffer");
		
		assert(doc->regions.size() == 6);
		is_int(3, doc->data_regions_count, "Document::data_regions_count");
		
		TEST_REGION_INT(0, REHex::Document::Region::Comment, d_offset, 0);
		TEST_REGION_STR(0, REHex::Document::Region::Comment, text,     "a");
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_offset, 0);
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_length, 1);
		
		TEST_REGION_INT(2, REHex::Document::Region::Comment, d_offset, 1);
		TEST_REGION_STR(2, REHex::Document::Region::Comment, text,     "b");
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_offset, 1);
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_length, 4);
		
		TEST_REGION_INT(4, REHex::Document::Region::Comment, d_offset, 5);
		TEST_REGION_STR(4, REHex::Document::Region::Comment, text,     "c");
		TEST_REGION_INT(5, REHex::Document::Region::Data,    d_offset, 5);
		TEST_REGION_INT(5, REHex::Document::Region::Data,    d_length, 4);
	}
	
	{
		diag("Erasing all of data region 1/3 in a Document");
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame, wxID_ANY, new REHex::Buffer());
		doc->SetSize(0,0, 640,480);
		
		unsigned char buffer_initial[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C};
		unsigned char buffer_final[]   = {0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C};
		
		doc->buffer->insert_data(0, buffer_initial, sizeof(buffer_initial));
		
		doc->regions.clear();
		doc->regions.push_back(new REHex::Document::Region::Comment(0,"a"));
		doc->regions.push_back(new REHex::Document::Region::Data(0,5));
		doc->regions.push_back(new REHex::Document::Region::Comment(5,"b"));
		doc->regions.push_back(new REHex::Document::Region::Data(5,4));
		doc->regions.push_back(new REHex::Document::Region::Comment(9,"c"));
		doc->regions.push_back(new REHex::Document::Region::Data(9,4));
		doc->data_regions_count = 3;
		
		wxClientDC dc(doc);
		doc->_erase_data(dc, 0, 5);
		
		is_int(sizeof(buffer_final), doc->buffer->length(), "Document::_erase_data() shrinks Buffer")
			&& is_blob(buffer_final, doc->buffer->read_data(0, 1024).data(), sizeof(buffer_final), "Document::_erase_data() erases correct data from Buffer");
		
		assert(doc->regions.size() == 4);
		is_int(2, doc->data_regions_count, "Document::data_regions_count");
		
		TEST_REGION_INT(0, REHex::Document::Region::Comment, d_offset, 0);
		TEST_REGION_STR(0, REHex::Document::Region::Comment, text,     "b");
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_offset, 0);
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_length, 4);
		
		TEST_REGION_INT(2, REHex::Document::Region::Comment, d_offset, 4);
		TEST_REGION_STR(2, REHex::Document::Region::Comment, text,     "c");
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_offset, 4);
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_length, 4);
	}
	
	{
		diag("Erasing the start of data region 2/3 in a Document");
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame, wxID_ANY, new REHex::Buffer());
		doc->SetSize(0,0, 640,480);
		
		unsigned char buffer_initial[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C};
		unsigned char buffer_final[]   = {0x00,0x01,0x02,0x03,0x04,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C};
		
		doc->buffer->insert_data(0, buffer_initial, sizeof(buffer_initial));
		
		doc->regions.clear();
		doc->regions.push_back(new REHex::Document::Region::Comment(0,"a"));
		doc->regions.push_back(new REHex::Document::Region::Data(0,5));
		doc->regions.push_back(new REHex::Document::Region::Comment(5,"b"));
		doc->regions.push_back(new REHex::Document::Region::Data(5,4));
		doc->regions.push_back(new REHex::Document::Region::Comment(9,"c"));
		doc->regions.push_back(new REHex::Document::Region::Data(9,4));
		doc->data_regions_count = 3;
		
		wxClientDC dc(doc);
		doc->_erase_data(dc, 5, 1);
		
		is_int(sizeof(buffer_final), doc->buffer->length(), "Document::_erase_data() shrinks Buffer")
			&& is_blob(buffer_final, doc->buffer->read_data(0, 1024).data(), sizeof(buffer_final), "Document::_erase_data() erases correct data from Buffer");
		
		assert(doc->regions.size() == 6);
		is_int(3, doc->data_regions_count, "Document::data_regions_count");
		
		TEST_REGION_INT(0, REHex::Document::Region::Comment, d_offset, 0);
		TEST_REGION_STR(0, REHex::Document::Region::Comment, text,     "a");
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_offset, 0);
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_length, 5);
		
		TEST_REGION_INT(2, REHex::Document::Region::Comment, d_offset, 5);
		TEST_REGION_STR(2, REHex::Document::Region::Comment, text,     "b");
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_offset, 5);
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_length, 3);
		
		TEST_REGION_INT(4, REHex::Document::Region::Comment, d_offset, 8);
		TEST_REGION_STR(4, REHex::Document::Region::Comment, text,     "c");
		TEST_REGION_INT(5, REHex::Document::Region::Data,    d_offset, 8);
		TEST_REGION_INT(5, REHex::Document::Region::Data,    d_length, 4);
	}
	
	{
		diag("Erasing the middle of data region 2/3 in a Document");
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame, wxID_ANY, new REHex::Buffer());
		doc->SetSize(0,0, 640,480);
		
		unsigned char buffer_initial[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C};
		unsigned char buffer_final[]   = {0x00,0x01,0x02,0x03,0x04,0x05,0x07,0x08,0x09,0x0A,0x0B,0x0C};
		
		doc->buffer->insert_data(0, buffer_initial, sizeof(buffer_initial));
		
		doc->regions.clear();
		doc->regions.push_back(new REHex::Document::Region::Comment(0,"a"));
		doc->regions.push_back(new REHex::Document::Region::Data(0,5));
		doc->regions.push_back(new REHex::Document::Region::Comment(5,"b"));
		doc->regions.push_back(new REHex::Document::Region::Data(5,4));
		doc->regions.push_back(new REHex::Document::Region::Comment(9,"c"));
		doc->regions.push_back(new REHex::Document::Region::Data(9,4));
		doc->data_regions_count = 3;
		
		wxClientDC dc(doc);
		doc->_erase_data(dc, 6, 1);
		
		is_int(sizeof(buffer_final), doc->buffer->length(), "Document::_erase_data() shrinks Buffer")
			&& is_blob(buffer_final, doc->buffer->read_data(0, 1024).data(), sizeof(buffer_final), "Document::_erase_data() erases correct data from Buffer");
		
		assert(doc->regions.size() == 6);
		is_int(3, doc->data_regions_count, "Document::data_regions_count");
		
		TEST_REGION_INT(0, REHex::Document::Region::Comment, d_offset, 0);
		TEST_REGION_STR(0, REHex::Document::Region::Comment, text,     "a");
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_offset, 0);
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_length, 5);
		
		TEST_REGION_INT(2, REHex::Document::Region::Comment, d_offset, 5);
		TEST_REGION_STR(2, REHex::Document::Region::Comment, text,     "b");
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_offset, 5);
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_length, 3);
		
		TEST_REGION_INT(4, REHex::Document::Region::Comment, d_offset, 8);
		TEST_REGION_STR(4, REHex::Document::Region::Comment, text,     "c");
		TEST_REGION_INT(5, REHex::Document::Region::Data,    d_offset, 8);
		TEST_REGION_INT(5, REHex::Document::Region::Data,    d_length, 4);
	}
	
	{
		diag("Erasing the end of data region 2/3 in a Document");
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame, wxID_ANY, new REHex::Buffer());
		doc->SetSize(0,0, 640,480);
		
		unsigned char buffer_initial[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C};
		unsigned char buffer_final[]   = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x09,0x0A,0x0B,0x0C};
		
		doc->buffer->insert_data(0, buffer_initial, sizeof(buffer_initial));
		
		doc->regions.clear();
		doc->regions.push_back(new REHex::Document::Region::Comment(0,"a"));
		doc->regions.push_back(new REHex::Document::Region::Data(0,5));
		doc->regions.push_back(new REHex::Document::Region::Comment(5,"b"));
		doc->regions.push_back(new REHex::Document::Region::Data(5,4));
		doc->regions.push_back(new REHex::Document::Region::Comment(9,"c"));
		doc->regions.push_back(new REHex::Document::Region::Data(9,4));
		doc->data_regions_count = 3;
		
		wxClientDC dc(doc);
		doc->_erase_data(dc, 8, 1);
		
		is_int(sizeof(buffer_final), doc->buffer->length(), "Document::_erase_data() shrinks Buffer")
			&& is_blob(buffer_final, doc->buffer->read_data(0, 1024).data(), sizeof(buffer_final), "Document::_erase_data() erases correct data from Buffer");
		
		assert(doc->regions.size() == 6);
		is_int(3, doc->data_regions_count, "Document::data_regions_count");
		
		TEST_REGION_INT(0, REHex::Document::Region::Comment, d_offset, 0);
		TEST_REGION_STR(0, REHex::Document::Region::Comment, text,     "a");
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_offset, 0);
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_length, 5);
		
		TEST_REGION_INT(2, REHex::Document::Region::Comment, d_offset, 5);
		TEST_REGION_STR(2, REHex::Document::Region::Comment, text,     "b");
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_offset, 5);
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_length, 3);
		
		TEST_REGION_INT(4, REHex::Document::Region::Comment, d_offset, 8);
		TEST_REGION_STR(4, REHex::Document::Region::Comment, text,     "c");
		TEST_REGION_INT(5, REHex::Document::Region::Data,    d_offset, 8);
		TEST_REGION_INT(5, REHex::Document::Region::Data,    d_length, 4);
	}
	
	{
		diag("Erasing all of data region 2/3 in a Document");
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame, wxID_ANY, new REHex::Buffer());
		doc->SetSize(0,0, 640,480);
		
		unsigned char buffer_initial[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C};
		unsigned char buffer_final[]   = {0x00,0x01,0x02,0x03,0x04,0x09,0x0A,0x0B,0x0C};
		
		doc->buffer->insert_data(0, buffer_initial, sizeof(buffer_initial));
		
		doc->regions.clear();
		doc->regions.push_back(new REHex::Document::Region::Comment(0,"a"));
		doc->regions.push_back(new REHex::Document::Region::Data(0,5));
		doc->regions.push_back(new REHex::Document::Region::Comment(5,"b"));
		doc->regions.push_back(new REHex::Document::Region::Data(5,4));
		doc->regions.push_back(new REHex::Document::Region::Comment(9,"c"));
		doc->regions.push_back(new REHex::Document::Region::Data(9,4));
		doc->data_regions_count = 3;
		
		wxClientDC dc(doc);
		doc->_erase_data(dc, 5, 4);
		
		is_int(sizeof(buffer_final), doc->buffer->length(), "Document::_erase_data() shrinks Buffer")
			&& is_blob(buffer_final, doc->buffer->read_data(0, 1024).data(), sizeof(buffer_final), "Document::_erase_data() erases correct data from Buffer");
		
		assert(doc->regions.size() == 4);
		is_int(2, doc->data_regions_count, "Document::data_regions_count");
		
		TEST_REGION_INT(0, REHex::Document::Region::Comment, d_offset, 0);
		TEST_REGION_STR(0, REHex::Document::Region::Comment, text,     "a");
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_offset, 0);
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_length, 5);
		
		TEST_REGION_INT(2, REHex::Document::Region::Comment, d_offset, 5);
		TEST_REGION_STR(2, REHex::Document::Region::Comment, text,     "c");
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_offset, 5);
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_length, 4);
	}
	
	{
		diag("Erasing the start of data region 3/3 in a Document");
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame, wxID_ANY, new REHex::Buffer());
		doc->SetSize(0,0, 640,480);
		
		unsigned char buffer_initial[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C};
		unsigned char buffer_final[]   = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x0C};
		
		doc->buffer->insert_data(0, buffer_initial, sizeof(buffer_initial));
		
		doc->regions.clear();
		doc->regions.push_back(new REHex::Document::Region::Comment(0,"a"));
		doc->regions.push_back(new REHex::Document::Region::Data(0,5));
		doc->regions.push_back(new REHex::Document::Region::Comment(5,"b"));
		doc->regions.push_back(new REHex::Document::Region::Data(5,4));
		doc->regions.push_back(new REHex::Document::Region::Comment(9,"c"));
		doc->regions.push_back(new REHex::Document::Region::Data(9,4));
		doc->data_regions_count = 3;
		
		wxClientDC dc(doc);
		doc->_erase_data(dc, 9, 3);
		
		is_int(sizeof(buffer_final), doc->buffer->length(), "Document::_erase_data() shrinks Buffer")
			&& is_blob(buffer_final, doc->buffer->read_data(0, 1024).data(), sizeof(buffer_final), "Document::_erase_data() erases correct data from Buffer");
		
		assert(doc->regions.size() == 6);
		is_int(3, doc->data_regions_count, "Document::data_regions_count");
		
		TEST_REGION_INT(0, REHex::Document::Region::Comment, d_offset, 0);
		TEST_REGION_STR(0, REHex::Document::Region::Comment, text,     "a");
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_offset, 0);
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_length, 5);
		
		TEST_REGION_INT(2, REHex::Document::Region::Comment, d_offset, 5);
		TEST_REGION_STR(2, REHex::Document::Region::Comment, text,     "b");
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_offset, 5);
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_length, 4);
		
		TEST_REGION_INT(4, REHex::Document::Region::Comment, d_offset, 9);
		TEST_REGION_STR(4, REHex::Document::Region::Comment, text,     "c");
		TEST_REGION_INT(5, REHex::Document::Region::Data,    d_offset, 9);
		TEST_REGION_INT(5, REHex::Document::Region::Data,    d_length, 1);
	}
	
	{
		diag("Erasing the middle of data region 3/3 in a Document");
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame, wxID_ANY, new REHex::Buffer());
		doc->SetSize(0,0, 640,480);
		
		unsigned char buffer_initial[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C};
		unsigned char buffer_final[]   = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0C};
		
		doc->buffer->insert_data(0, buffer_initial, sizeof(buffer_initial));
		
		doc->regions.clear();
		doc->regions.push_back(new REHex::Document::Region::Comment(0,"a"));
		doc->regions.push_back(new REHex::Document::Region::Data(0,5));
		doc->regions.push_back(new REHex::Document::Region::Comment(5,"b"));
		doc->regions.push_back(new REHex::Document::Region::Data(5,4));
		doc->regions.push_back(new REHex::Document::Region::Comment(9,"c"));
		doc->regions.push_back(new REHex::Document::Region::Data(9,4));
		doc->data_regions_count = 3;
		
		wxClientDC dc(doc);
		doc->_erase_data(dc, 11, 1);
		
		is_int(sizeof(buffer_final), doc->buffer->length(), "Document::_erase_data() shrinks Buffer")
			&& is_blob(buffer_final, doc->buffer->read_data(0, 1024).data(), sizeof(buffer_final), "Document::_erase_data() erases correct data from Buffer");
		
		assert(doc->regions.size() == 6);
		is_int(3, doc->data_regions_count, "Document::data_regions_count");
		
		TEST_REGION_INT(0, REHex::Document::Region::Comment, d_offset, 0);
		TEST_REGION_STR(0, REHex::Document::Region::Comment, text,     "a");
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_offset, 0);
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_length, 5);
		
		TEST_REGION_INT(2, REHex::Document::Region::Comment, d_offset, 5);
		TEST_REGION_STR(2, REHex::Document::Region::Comment, text,     "b");
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_offset, 5);
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_length, 4);
		
		TEST_REGION_INT(4, REHex::Document::Region::Comment, d_offset, 9);
		TEST_REGION_STR(4, REHex::Document::Region::Comment, text,     "c");
		TEST_REGION_INT(5, REHex::Document::Region::Data,    d_offset, 9);
		TEST_REGION_INT(5, REHex::Document::Region::Data,    d_length, 3);
	}
	
	{
		diag("Erasing the end of data region 3/3 in a Document");
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame, wxID_ANY, new REHex::Buffer());
		doc->SetSize(0,0, 640,480);
		
		unsigned char buffer_initial[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C};
		unsigned char buffer_final[]   = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09};
		
		doc->buffer->insert_data(0, buffer_initial, sizeof(buffer_initial));
		
		doc->regions.clear();
		doc->regions.push_back(new REHex::Document::Region::Comment(0,"a"));
		doc->regions.push_back(new REHex::Document::Region::Data(0,5));
		doc->regions.push_back(new REHex::Document::Region::Comment(5,"b"));
		doc->regions.push_back(new REHex::Document::Region::Data(5,4));
		doc->regions.push_back(new REHex::Document::Region::Comment(9,"c"));
		doc->regions.push_back(new REHex::Document::Region::Data(9,4));
		doc->data_regions_count = 3;
		
		wxClientDC dc(doc);
		doc->_erase_data(dc, 10, 3);
		
		is_int(sizeof(buffer_final), doc->buffer->length(), "Document::_erase_data() shrinks Buffer")
			&& is_blob(buffer_final, doc->buffer->read_data(0, 1024).data(), sizeof(buffer_final), "Document::_erase_data() erases correct data from Buffer");
		
		assert(doc->regions.size() == 6);
		is_int(3, doc->data_regions_count, "Document::data_regions_count");
		
		TEST_REGION_INT(0, REHex::Document::Region::Comment, d_offset, 0);
		TEST_REGION_STR(0, REHex::Document::Region::Comment, text,     "a");
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_offset, 0);
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_length, 5);
		
		TEST_REGION_INT(2, REHex::Document::Region::Comment, d_offset, 5);
		TEST_REGION_STR(2, REHex::Document::Region::Comment, text,     "b");
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_offset, 5);
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_length, 4);
		
		TEST_REGION_INT(4, REHex::Document::Region::Comment, d_offset, 9);
		TEST_REGION_STR(4, REHex::Document::Region::Comment, text,     "c");
		TEST_REGION_INT(5, REHex::Document::Region::Data,    d_offset, 9);
		TEST_REGION_INT(5, REHex::Document::Region::Data,    d_length, 1);
	}
	
	{
		diag("Erasing all of data region 3/3 in a Document");
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame, wxID_ANY, new REHex::Buffer());
		doc->SetSize(0,0, 640,480);
		
		unsigned char buffer_initial[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C};
		unsigned char buffer_final[]   = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08};
		
		doc->buffer->insert_data(0, buffer_initial, sizeof(buffer_initial));
		
		doc->regions.clear();
		doc->regions.push_back(new REHex::Document::Region::Comment(0,"a"));
		doc->regions.push_back(new REHex::Document::Region::Data(0,5));
		doc->regions.push_back(new REHex::Document::Region::Comment(5,"b"));
		doc->regions.push_back(new REHex::Document::Region::Data(5,4));
		doc->regions.push_back(new REHex::Document::Region::Comment(9,"c"));
		doc->regions.push_back(new REHex::Document::Region::Data(9,4));
		doc->data_regions_count = 3;
		
		wxClientDC dc(doc);
		doc->_erase_data(dc, 9, 4);
		
		is_int(sizeof(buffer_final), doc->buffer->length(), "Document::_erase_data() shrinks Buffer")
			&& is_blob(buffer_final, doc->buffer->read_data(0, 1024).data(), sizeof(buffer_final), "Document::_erase_data() erases correct data from Buffer");
		
		assert(doc->regions.size() == 4);
		is_int(2, doc->data_regions_count, "Document::data_regions_count");
		
		TEST_REGION_INT(0, REHex::Document::Region::Comment, d_offset, 0);
		TEST_REGION_STR(0, REHex::Document::Region::Comment, text,     "a");
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_offset, 0);
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_length, 5);
		
		TEST_REGION_INT(2, REHex::Document::Region::Comment, d_offset, 5);
		TEST_REGION_STR(2, REHex::Document::Region::Comment, text,     "b");
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_offset, 5);
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_length, 4);
	}
	
	{
		diag("Erasing some of data region 1/3 and 2/3 in a Document");
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame, wxID_ANY, new REHex::Buffer());
		doc->SetSize(0,0, 640,480);
		
		unsigned char buffer_initial[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C};
		unsigned char buffer_final[]   = {0x00,0x01,0x02,0x07,0x08,0x09,0x0A,0x0B,0x0C};
		
		doc->buffer->insert_data(0, buffer_initial, sizeof(buffer_initial));
		
		doc->regions.clear();
		doc->regions.push_back(new REHex::Document::Region::Comment(0,"a"));
		doc->regions.push_back(new REHex::Document::Region::Data(0,5));
		doc->regions.push_back(new REHex::Document::Region::Comment(5,"b"));
		doc->regions.push_back(new REHex::Document::Region::Data(5,4));
		doc->regions.push_back(new REHex::Document::Region::Comment(9,"c"));
		doc->regions.push_back(new REHex::Document::Region::Data(9,4));
		doc->data_regions_count = 3;
		
		wxClientDC dc(doc);
		doc->_erase_data(dc, 3, 4);
		
		is_int(sizeof(buffer_final), doc->buffer->length(), "Document::_erase_data() shrinks Buffer")
			&& is_blob(buffer_final, doc->buffer->read_data(0, 1024).data(), sizeof(buffer_final), "Document::_erase_data() erases correct data from Buffer");
		
		assert(doc->regions.size() == 6);
		is_int(3, doc->data_regions_count, "Document::data_regions_count");
		
		TEST_REGION_INT(0, REHex::Document::Region::Comment, d_offset, 0);
		TEST_REGION_STR(0, REHex::Document::Region::Comment, text,     "a");
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_offset, 0);
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_length, 3);
		
		TEST_REGION_INT(2, REHex::Document::Region::Comment, d_offset, 3);
		TEST_REGION_STR(2, REHex::Document::Region::Comment, text,     "b");
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_offset, 3);
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_length, 2);
		
		TEST_REGION_INT(4, REHex::Document::Region::Comment, d_offset, 5);
		TEST_REGION_STR(4, REHex::Document::Region::Comment, text,     "c");
		TEST_REGION_INT(5, REHex::Document::Region::Data,    d_offset, 5);
		TEST_REGION_INT(5, REHex::Document::Region::Data,    d_length, 4);
	}
	
	{
		diag("Erasing some of data region 1/3 and all of 2/3 in a Document");
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame, wxID_ANY, new REHex::Buffer());
		doc->SetSize(0,0, 640,480);
		
		unsigned char buffer_initial[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C};
		unsigned char buffer_final[]   = {0x00,0x01,0x02,0x09,0x0A,0x0B,0x0C};
		
		doc->buffer->insert_data(0, buffer_initial, sizeof(buffer_initial));
		
		doc->regions.clear();
		doc->regions.push_back(new REHex::Document::Region::Comment(0,"a"));
		doc->regions.push_back(new REHex::Document::Region::Data(0,5));
		doc->regions.push_back(new REHex::Document::Region::Comment(5,"b"));
		doc->regions.push_back(new REHex::Document::Region::Data(5,4));
		doc->regions.push_back(new REHex::Document::Region::Comment(9,"c"));
		doc->regions.push_back(new REHex::Document::Region::Data(9,4));
		doc->data_regions_count = 3;
		
		wxClientDC dc(doc);
		doc->_erase_data(dc, 3, 6);
		
		is_int(sizeof(buffer_final), doc->buffer->length(), "Document::_erase_data() shrinks Buffer")
			&& is_blob(buffer_final, doc->buffer->read_data(0, 1024).data(), sizeof(buffer_final), "Document::_erase_data() erases correct data from Buffer");
		
		assert(doc->regions.size() == 4);
		is_int(2, doc->data_regions_count, "Document::data_regions_count");
		
		TEST_REGION_INT(0, REHex::Document::Region::Comment, d_offset, 0);
		TEST_REGION_STR(0, REHex::Document::Region::Comment, text,     "a");
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_offset, 0);
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_length, 3);
		
		TEST_REGION_INT(2, REHex::Document::Region::Comment, d_offset, 3);
		TEST_REGION_STR(2, REHex::Document::Region::Comment, text,     "c");
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_offset, 3);
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_length, 4);
	}
	
	{
		diag("Erasing all of data region 1/3 and some of 2/3 in a Document");
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame, wxID_ANY, new REHex::Buffer());
		doc->SetSize(0,0, 640,480);
		
		unsigned char buffer_initial[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C};
		unsigned char buffer_final[]   = {0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C};
		
		doc->buffer->insert_data(0, buffer_initial, sizeof(buffer_initial));
		
		doc->regions.clear();
		doc->regions.push_back(new REHex::Document::Region::Comment(0,"a"));
		doc->regions.push_back(new REHex::Document::Region::Data(0,5));
		doc->regions.push_back(new REHex::Document::Region::Comment(5,"b"));
		doc->regions.push_back(new REHex::Document::Region::Data(5,4));
		doc->regions.push_back(new REHex::Document::Region::Comment(9,"c"));
		doc->regions.push_back(new REHex::Document::Region::Data(9,4));
		doc->data_regions_count = 3;
		
		wxClientDC dc(doc);
		doc->_erase_data(dc, 0, 6);
		
		is_int(sizeof(buffer_final), doc->buffer->length(), "Document::_erase_data() shrinks Buffer")
			&& is_blob(buffer_final, doc->buffer->read_data(0, 1024).data(), sizeof(buffer_final), "Document::_erase_data() erases correct data from Buffer");
		
		assert(doc->regions.size() == 4);
		is_int(2, doc->data_regions_count, "Document::data_regions_count");
		
		TEST_REGION_INT(0, REHex::Document::Region::Comment, d_offset, 0);
		TEST_REGION_STR(0, REHex::Document::Region::Comment, text,     "b");
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_offset, 0);
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_length, 3);
		
		TEST_REGION_INT(2, REHex::Document::Region::Comment, d_offset, 3);
		TEST_REGION_STR(2, REHex::Document::Region::Comment, text,     "c");
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_offset, 3);
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_length, 4);
	}
	
	{
		diag("Erasing some of data region 1/3, all of 2/3 and some of 3/3 in a Document");
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame, wxID_ANY, new REHex::Buffer());
		doc->SetSize(0,0, 640,480);
		
		unsigned char buffer_initial[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C};
		unsigned char buffer_final[]   = {0x00,0x01,0x02,0x03,0x0B,0x0C};
		
		doc->buffer->insert_data(0, buffer_initial, sizeof(buffer_initial));
		
		doc->regions.clear();
		doc->regions.push_back(new REHex::Document::Region::Comment(0,"a"));
		doc->regions.push_back(new REHex::Document::Region::Data(0,5));
		doc->regions.push_back(new REHex::Document::Region::Comment(5,"b"));
		doc->regions.push_back(new REHex::Document::Region::Data(5,4));
		doc->regions.push_back(new REHex::Document::Region::Comment(9,"c"));
		doc->regions.push_back(new REHex::Document::Region::Data(9,4));
		doc->data_regions_count = 3;
		
		wxClientDC dc(doc);
		doc->_erase_data(dc, 4, 7);
		
		is_int(sizeof(buffer_final), doc->buffer->length(), "Document::_erase_data() shrinks Buffer")
			&& is_blob(buffer_final, doc->buffer->read_data(0, 1024).data(), sizeof(buffer_final), "Document::_erase_data() erases correct data from Buffer");
		
		assert(doc->regions.size() == 4);
		is_int(2, doc->data_regions_count, "Document::data_regions_count");
		
		TEST_REGION_INT(0, REHex::Document::Region::Comment, d_offset, 0);
		TEST_REGION_STR(0, REHex::Document::Region::Comment, text,     "a");
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_offset, 0);
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_length, 4);
		
		TEST_REGION_INT(2, REHex::Document::Region::Comment, d_offset, 4);
		TEST_REGION_STR(2, REHex::Document::Region::Comment, text,     "c");
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_offset, 4);
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_length, 2);
	}
	
	{
		diag("Erasing some of data region 2/3, and some of 3/3 in a Document");
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame, wxID_ANY, new REHex::Buffer());
		doc->SetSize(0,0, 640,480);
		
		unsigned char buffer_initial[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C};
		unsigned char buffer_final[]   = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x0A,0x0B,0x0C};
		
		doc->buffer->insert_data(0, buffer_initial, sizeof(buffer_initial));
		
		doc->regions.clear();
		doc->regions.push_back(new REHex::Document::Region::Comment(0,"a"));
		doc->regions.push_back(new REHex::Document::Region::Data(0,5));
		doc->regions.push_back(new REHex::Document::Region::Comment(5,"b"));
		doc->regions.push_back(new REHex::Document::Region::Data(5,4));
		doc->regions.push_back(new REHex::Document::Region::Comment(9,"c"));
		doc->regions.push_back(new REHex::Document::Region::Data(9,4));
		doc->data_regions_count = 3;
		
		wxClientDC dc(doc);
		doc->_erase_data(dc, 8, 2);
		
		is_int(sizeof(buffer_final), doc->buffer->length(), "Document::_erase_data() shrinks Buffer")
			&& is_blob(buffer_final, doc->buffer->read_data(0, 1024).data(), sizeof(buffer_final), "Document::_erase_data() erases correct data from Buffer");
		
		assert(doc->regions.size() == 6);
		is_int(3, doc->data_regions_count, "Document::data_regions_count");
		
		TEST_REGION_INT(0, REHex::Document::Region::Comment, d_offset, 0);
		TEST_REGION_STR(0, REHex::Document::Region::Comment, text,     "a");
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_offset, 0);
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_length, 5);
		
		TEST_REGION_INT(2, REHex::Document::Region::Comment, d_offset, 5);
		TEST_REGION_STR(2, REHex::Document::Region::Comment, text,     "b");
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_offset, 5);
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_length, 3);
		
		TEST_REGION_INT(4, REHex::Document::Region::Comment, d_offset, 8);
		TEST_REGION_STR(4, REHex::Document::Region::Comment, text,     "c");
		TEST_REGION_INT(5, REHex::Document::Region::Data,    d_offset, 8);
		TEST_REGION_INT(5, REHex::Document::Region::Data,    d_length, 3);
	}
	
	{
		diag("Erasing some of data region 2/3, and all of 3/3 in a Document");
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame, wxID_ANY, new REHex::Buffer());
		doc->SetSize(0,0, 640,480);
		
		unsigned char buffer_initial[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C};
		unsigned char buffer_final[]   = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07};
		
		doc->buffer->insert_data(0, buffer_initial, sizeof(buffer_initial));
		
		doc->regions.clear();
		doc->regions.push_back(new REHex::Document::Region::Comment(0,"a"));
		doc->regions.push_back(new REHex::Document::Region::Data(0,5));
		doc->regions.push_back(new REHex::Document::Region::Comment(5,"b"));
		doc->regions.push_back(new REHex::Document::Region::Data(5,4));
		doc->regions.push_back(new REHex::Document::Region::Comment(9,"c"));
		doc->regions.push_back(new REHex::Document::Region::Data(9,4));
		doc->data_regions_count = 3;
		
		wxClientDC dc(doc);
		doc->_erase_data(dc, 8, 5);
		
		is_int(sizeof(buffer_final), doc->buffer->length(), "Document::_erase_data() shrinks Buffer")
			&& is_blob(buffer_final, doc->buffer->read_data(0, 1024).data(), sizeof(buffer_final), "Document::_erase_data() erases correct data from Buffer");
		
		assert(doc->regions.size() == 4);
		is_int(2, doc->data_regions_count, "Document::data_regions_count");
		
		TEST_REGION_INT(0, REHex::Document::Region::Comment, d_offset, 0);
		TEST_REGION_STR(0, REHex::Document::Region::Comment, text,     "a");
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_offset, 0);
		TEST_REGION_INT(1, REHex::Document::Region::Data,    d_length, 5);
		
		TEST_REGION_INT(2, REHex::Document::Region::Comment, d_offset, 5);
		TEST_REGION_STR(2, REHex::Document::Region::Comment, text,     "b");
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_offset, 5);
		TEST_REGION_INT(3, REHex::Document::Region::Data,    d_length, 3);
	}
	
	{
		diag("Erasing all data from a Document with 3 data regions");
		
		wxFrame frame(NULL, wxID_ANY, wxT("Unit tests"));
		REHex::Document *doc = new REHex::Document(&frame, wxID_ANY, new REHex::Buffer());
		doc->SetSize(0,0, 640,480);
		
		unsigned char buffer_initial[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C};
		unsigned char buffer_final[]   = {};
		
		doc->buffer->insert_data(0, buffer_initial, sizeof(buffer_initial));
		
		doc->regions.clear();
		doc->regions.push_back(new REHex::Document::Region::Comment(0,"a"));
		doc->regions.push_back(new REHex::Document::Region::Data(0,5));
		doc->regions.push_back(new REHex::Document::Region::Comment(5,"b"));
		doc->regions.push_back(new REHex::Document::Region::Data(5,4));
		doc->regions.push_back(new REHex::Document::Region::Comment(9,"c"));
		doc->regions.push_back(new REHex::Document::Region::Data(9,4));
		doc->data_regions_count = 3;
		
		wxClientDC dc(doc);
		doc->_erase_data(dc, 0, 13);
		
		is_int(sizeof(buffer_final), doc->buffer->length(), "Document::_erase_data() shrinks Buffer")
			&& is_blob(buffer_final, doc->buffer->read_data(0, 1024).data(), sizeof(buffer_final), "Document::_erase_data() erases correct data from Buffer");
		
		assert(doc->regions.size() == 1);
		is_int(1, doc->data_regions_count, "Document::data_regions_count");
		
		TEST_REGION_INT(0, REHex::Document::Region::Data, d_offset, 0);
		TEST_REGION_INT(0, REHex::Document::Region::Data, d_length, 0);
	}
	
	/* TODO: Check y_* values */
}

int main(int argc, char **argv)
{
	wxApp::SetInstance(new wxApp());
	wxEntryStart(argc, argv);
	wxTheApp->OnInit();
	
	plan_lazy();
	
	insert_tests();
	erase_tests();
	
	wxTheApp->OnExit();
	wxEntryCleanup();
	
	return 0;
}
