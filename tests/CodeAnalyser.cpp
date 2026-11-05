/* Reverse Engineer's Hex Editor
 * Copyright (C) 2020-2026 Daniel Collins <solemnwarning@solemnwarning.net>
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
#include <chrono>
#include <memory>

#include "../src/App.hpp"
#include "../src/CodeAnalyser.hpp"
#include "../src/document.hpp"
#include "../src/SharedDocumentPointer.hpp"
#include "testutil.hpp"

using namespace REHex;

#define EXPECT_INSTRUCTION_BYTES(instr, ...) \
{ \
	std::vector<unsigned char> REFERENCE_BYTES = { __VA_ARGS__ }; \
	EXPECT_EQ(instr.length(), REFERENCE_BYTES.size()); \
	unsigned char *instr_bytes = (unsigned char*)(instr.instruction()); \
	EXPECT_EQ(std::vector<unsigned char>(instr_bytes, (instr_bytes + instr.length())), REFERENCE_BYTES); \
}

#define EXPECT_INSTRUCTION_BY_OFFSET(at_offset, expect_offset, expect_line, expect_assembly, ...) \
{ \
	CodeAnalyser::Instruction inst = analyser->instruction_by_abs_offset(at_offset); \
	EXPECT_TRUE(inst) << "CodeAnalyser::instruction_by_abs_offset() returns a valid instruction"; \
	\
	if(inst) \
	{ \
		EXPECT_EQ(inst.offset(), expect_offset) << "CodeAnalyser::instruction_by_abs_offset() returns the correct instruction offset"; \
		EXPECT_EQ(inst.line(), expect_line) << "CodeAnalyser::instruction_by_abs_offset() returns the correct instruction line"; \
		\
		EXPECT_INSTRUCTION_BYTES(inst, __VA_ARGS__); \
		EXPECT_EQ(inst.assembly(), expect_assembly) << "CodeAnalyser::instruction_by_abs_offset() returns the correct disassembly"; \
	} \
}

#define EXPECT_INSTRUCTION_BY_LINE(base_offset, at_line, expect_offset, expect_line, expect_assembly, ...) \
{ \
	CodeAnalyser::Instruction inst = analyser->instruction_by_line(base_offset, at_line); \
	EXPECT_TRUE(inst) << "CodeAnalyser::instruction_by_line() returns a valid instruction"; \
	\
	if(inst) \
	{ \
		EXPECT_EQ(inst.offset(), expect_offset) << "CodeAnalyser::instruction_by_line() returns the correct instruction offset"; \
		EXPECT_EQ(inst.line(), expect_line) << "CodeAnalyser::instruction_by_line() returns the correct instruction line"; \
		\
		EXPECT_INSTRUCTION_BYTES(inst, __VA_ARGS__); \
		EXPECT_EQ(inst.assembly(), expect_assembly) << "CodeAnalyser::instruction_by_line() returns the correct disassembly"; \
	} \
}

TEST(CodeAnalyser, ProcessFile)
{
	/* Open test executable. */
	SharedDocumentPointer doc(SharedDocumentPointer::make(wxFileName("tests/ls.x86_64")));
	
	std::unique_ptr<ThreadPoolJammer> tpj(new ThreadPoolJammer(wxGetApp().thread_pool));
	
	/* Create CodeAnalyser covering the entire .text section */
	std::unique_ptr<CodeAnalyser> analyser(new CodeAnalyser(doc, 0x46F0, 0x125BE, CS_ARCH_X86, CS_MODE_64));
	
	/* Ensure no data is initially processed. */
	
	{
		CodeAnalyser::AnalysisPosition ap = analyser->get_analysis_position();
		
		EXPECT_EQ(ap.offset, 0x46F0);
		EXPECT_EQ(ap.line, 0);
	}
	
	{
		CodeAnalyser::Instruction inst = analyser->instruction_by_abs_offset(0x46F0);
		EXPECT_FALSE(inst);
	}
	
	{
		CodeAnalyser::Instruction inst = analyser->instruction_by_abs_offset(0x5000);
		EXPECT_FALSE(inst);
	}
	
	{
		CodeAnalyser::Instruction inst = analyser->instruction_by_line(0x46F0, 0);
		EXPECT_FALSE(inst);
	}
	
	{
		CodeAnalyser::Instruction inst = analyser->instruction_by_line(0x46F0, 100);
		EXPECT_FALSE(inst);
	}
	
	/* Allow the background analysis task to run once. */
	
	tpj->yield(1);
	
	{
		CodeAnalyser::AnalysisPosition ap = analyser->get_analysis_position();
		
		EXPECT_EQ(ap.offset, 0x6EF4);
		EXPECT_EQ(ap.line, 2237);
	}
	
	/* Check instruction_by_abs_offset() method returns instructions within processed area only. */
	
	EXPECT_INSTRUCTION_BY_OFFSET(0x46F0,
		BitOffset(0x46F0, 0),
		0,
		"call    0x4080",
		0xE8, 0x8B, 0xF9, 0xFF, 0xFF);
	
	EXPECT_INSTRUCTION_BY_OFFSET(0x46F4,
		BitOffset(0x46F0, 0),
		0,
		"call    0x4080",
		0xE8, 0x8B, 0xF9, 0xFF, 0xFF);
	
	EXPECT_INSTRUCTION_BY_OFFSET(0x46F5,
		BitOffset(0x46F5, 0),
		1,
		"call    0x4080",
		0xE8, 0x86, 0xF9, 0xFF, 0xFF);
	
	EXPECT_INSTRUCTION_BY_OFFSET(0x6EF3,
		BitOffset(0x6EED, 0),
		2236,
		"mov     rcx, qword ptr [rip + 0x1c74c]",
		0x48, 0x8B, 0x0D, 0x4C, 0xC7, 0x01, 0x00);
	
	{
		CodeAnalyser::Instruction inst = analyser->instruction_by_abs_offset(0x6EF4);
		EXPECT_FALSE(inst);
	}
	
	/* Check instruction_by_line() method returns instructions in processed area only. */
	
	EXPECT_INSTRUCTION_BY_LINE(0x46F0, 0,
		BitOffset(0x46F0, 0),
		0,
		"call    0x4080",
		0xE8, 0x8B, 0xF9, 0xFF, 0xFF);
	
	EXPECT_INSTRUCTION_BY_LINE(0x46F0, 1,
		BitOffset(0x46F5, 0),
		1,
		"call    0x4080",
		0xE8, 0x86, 0xF9, 0xFF, 0xFF);
	
	EXPECT_INSTRUCTION_BY_LINE(0x46F0, 2236,
		BitOffset(0x6EED, 0),
		2236,
		"mov     rcx, qword ptr [rip + 0x1c74c]",
		0x48, 0x8B, 0x0D, 0x4C, 0xC7, 0x01, 0x00);
	
	{
		CodeAnalyser::Instruction inst = analyser->instruction_by_line(0x46F0, 2237);
		EXPECT_FALSE(inst);
	}
	
	/* Check instruction_by_line() returns lines relative to arbitrary offset. */
	
	EXPECT_INSTRUCTION_BY_LINE(0x4727, 0,
		BitOffset(0x4727, 0),
		11,
		"nop     word ptr [rax + rax]",
		0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00);
	
	EXPECT_INSTRUCTION_BY_LINE(0x472A, 0,
		BitOffset(0x4727, 0),
		11,
		"nop     word ptr [rax + rax]",
		0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00);
	
	EXPECT_INSTRUCTION_BY_LINE(0x472A, 1,
		BitOffset(0x4730, 0),
		12,
		"push    r15",
		0x41, 0x57);
	
	EXPECT_INSTRUCTION_BY_LINE(0x4727, 2225,
		BitOffset(0x6EED, 0),
		2236,
		"mov     rcx, qword ptr [rip + 0x1c74c]",
		0x48, 0x8B, 0x0D, 0x4C, 0xC7, 0x01, 0x00);
	
	/* Allow analysis to run to completion. */
	
	tpj.reset();
	
	while(analyser->get_analysis_position().offset < (0x46F0 + 0x125BE))
	{
		std::this_thread::sleep_for(std::chrono::milliseconds(10));
	}
	
	{
		CodeAnalyser::AnalysisPosition ap = analyser->get_analysis_position();
		
		EXPECT_EQ(ap.offset, (0x46F0 + 0x125BE));
		EXPECT_EQ(ap.line, 18840);
	}
	
	/* Check instruction_by_abs_offset() method returns instructions from whole range. */
	
	EXPECT_INSTRUCTION_BY_OFFSET(0x46F0,
		BitOffset(0x46F0, 0),
		0,
		"call    0x4080",
		0xE8, 0x8B, 0xF9, 0xFF, 0xFF);
	
	EXPECT_INSTRUCTION_BY_OFFSET(0x46F5,
		BitOffset(0x46F5, 0),
		1,
		"call    0x4080",
		0xE8, 0x86, 0xF9, 0xFF, 0xFF);
	
	EXPECT_INSTRUCTION_BY_OFFSET(0x6EF3,
		BitOffset(0x6EED, 0),
		2236,
		"mov     rcx, qword ptr [rip + 0x1c74c]",
		0x48, 0x8B, 0x0D, 0x4C, 0xC7, 0x01, 0x00);
	
	EXPECT_INSTRUCTION_BY_OFFSET(0xDCD2,
		BitOffset(0xDCD2, 0),
		9182,
		"add     rbx, rax",
		0x48, 0x01, 0xC3);
	
	EXPECT_INSTRUCTION_BY_OFFSET(0x16CAD,
		BitOffset(0x16CA9, 0),
		18839,
		"jmp     0x45d0",
		0xE9, 0x22, 0xD9, 0xFE, 0xFF);
}

TEST(CodeAnalyser, InstructionSpanningEndOfRegion)
{
	/* Open test executable. */
	SharedDocumentPointer doc(SharedDocumentPointer::make(wxFileName("tests/ls.x86_64")));
	
	/* Create CodeAnalyser covering the entire .text section */
	std::unique_ptr<CodeAnalyser> analyser(new CodeAnalyser(doc, 0x46F0, 9, CS_ARCH_X86, CS_MODE_64));
	
	/* Wait for analysis to complete. */
	while(analyser->get_analysis_position().offset < (0x46F0 + 9))
	{
		std::this_thread::sleep_for(std::chrono::milliseconds(10));
	}
	
	{
		CodeAnalyser::AnalysisPosition ap = analyser->get_analysis_position();
		
		EXPECT_EQ(ap.offset, (0x46F0 + 9));
		EXPECT_EQ(ap.line, 4);
	}
	
	EXPECT_INSTRUCTION_BY_OFFSET(0x46F0,
		BitOffset(0x46F0, 0),
		0,
		"call    0x4080",
		0xE8, 0x8B, 0xF9, 0xFF, 0xFF);
	
	EXPECT_INSTRUCTION_BY_OFFSET(0x46F5,
		BitOffset(0x46F5, 0),
		1,
		".byte   0xe8",
		0xE8);
	
	EXPECT_INSTRUCTION_BY_OFFSET(0x46F6,
		BitOffset(0x46F6, 0),
		2,
		"xchg    cl, bh",
		0x86, 0xF9);
	
	EXPECT_INSTRUCTION_BY_OFFSET(0x46F8,
		BitOffset(0x46F8, 0),
		3,
		".byte   0xff",
		0xFF);
}

TEST(CodeAnalyser, InvalidInstructionAMD64)
{
	/* Prepare Document with test data. */
	SharedDocumentPointer doc(SharedDocumentPointer::make());
	
	const unsigned char DATA[] = {
		0x00, 0x01,  /* add     byte ptr [rcx], al */
		0x02, 0x03,  /* add     al, byte ptr [rbx] */
		0x04, 0x05,  /* add     al, 5 */
		0x06,
		0x07,
		0x08, 0x09,  /* or      byte ptr [rcx], cl */
		0x0A, 0x0B,  /* or      cl, byte ptr [rbx] */
		0x0C, 0x0D,  /* or      al, 0xd */
		0x0E,
	};
	
	doc->insert_data(0, DATA, sizeof(DATA));
	
	/* Create CodeAnalyser covering our test data */
	std::unique_ptr<CodeAnalyser> analyser(new CodeAnalyser(doc, 0, 15, CS_ARCH_X86, CS_MODE_64));
	
	/* Wait for analysis to complete. */
	while(analyser->get_analysis_position().offset < 15)
	{
		std::this_thread::sleep_for(std::chrono::milliseconds(10));
	}
	
	{
		CodeAnalyser::AnalysisPosition ap = analyser->get_analysis_position();
		
		EXPECT_EQ(ap.offset, 15);
		EXPECT_EQ(ap.line, 9);
	}
	
	EXPECT_INSTRUCTION_BY_OFFSET(0,
		BitOffset(0, 0),
		0,
		"add     byte ptr [rcx], al",
		0x00, 0x01);
	
	EXPECT_INSTRUCTION_BY_OFFSET(0x02,
		BitOffset(0x02, 0),
		1,
		"add     al, byte ptr [rbx]",
		0x02, 0x03);
	
	EXPECT_INSTRUCTION_BY_OFFSET(0x05,
		BitOffset(0x04, 0),
		2,
		"add     al, 5",
		0x04, 0x05);
	
	EXPECT_INSTRUCTION_BY_OFFSET(0x06,
		BitOffset(0x06, 0),
		3,
		".byte   0x06",
		0x06);
	
	EXPECT_INSTRUCTION_BY_OFFSET(0x07,
		BitOffset(0x07, 0),
		4,
		".byte   0x07",
		0x07);
	
	EXPECT_INSTRUCTION_BY_OFFSET(0x08,
		BitOffset(0x08, 0),
		5,
		"or      byte ptr [rcx], cl",
		0x08, 0x09);
	
	EXPECT_INSTRUCTION_BY_OFFSET(0x0E,
		BitOffset(0x0E, 0),
		8,
		".byte   0x0e",
		0x0E);
}

TEST(CodeAnalyser, InvalidInstructionARM64)
{
	/* Prepare Document with test data. */
	SharedDocumentPointer doc(SharedDocumentPointer::make());
	
	const unsigned char DATA[] = {
		0x04, 0x05, 0x06, 0x07,  /* .byte   0x04, 0x05, 0x06, 0x07 */
		0x08, 0x09, 0x0A, 0x0B,  /* add     w8, w8, w10, lsl #2 */
		0x0C, 0x0D, 0x0E, 0x0F,  /* .byte   0x0c, 0x0d, 0x0e, 0x0f */
		0x10, 0x11, 0x12, 0x13,  /* sbfiz   w16, w8, #0xe, #5 */
		0x14,                    /* .byte   0x14 */
		0x15,                    /* .byte   0x15 */
		
		0x00, 0x00, 0x00, 0x00,
	};
	
	doc->insert_data(0, DATA, sizeof(DATA));
	
	/* Create CodeAnalyser covering our test data */
	std::unique_ptr<CodeAnalyser> analyser(new CodeAnalyser(doc, 0, 18, CS_ARCH_ARM64, (cs_mode)(CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)));
	
	/* Wait for analysis to complete. */
	while(analyser->get_analysis_position().offset < 18)
	{
		std::this_thread::sleep_for(std::chrono::milliseconds(10));
	}
	
	{
		CodeAnalyser::AnalysisPosition ap = analyser->get_analysis_position();
		
		EXPECT_EQ(ap.offset, 18);
		EXPECT_EQ(ap.line, 6);
	}
	
	EXPECT_INSTRUCTION_BY_OFFSET(0,
		BitOffset(0, 0),
		0,
		".byte   0x04, 0x05, 0x06, 0x07",
		0x04, 0x05, 0x06, 0x07);
	
	EXPECT_INSTRUCTION_BY_OFFSET(0x04,
		BitOffset(0x04, 0),
		1,
		"add     w8, w8, w10, lsl #2",
		0x08, 0x09, 0x0A, 0x0B);
	
	EXPECT_INSTRUCTION_BY_OFFSET(0x08,
		BitOffset(0x08, 0),
		2,
		".byte   0x0c, 0x0d, 0x0e, 0x0f",
		0x0C, 0x0D, 0x0E, 0x0F);
	
	EXPECT_INSTRUCTION_BY_OFFSET(0x0C,
		BitOffset(0x0C, 0),
		3,
		"sbfiz   w16, w8, #0xe, #5",
		0x10, 0x11, 0x12, 0x13);
	
	EXPECT_INSTRUCTION_BY_OFFSET(0x10,
		BitOffset(0x10, 0),
		4,
		".byte   0x14",
		0x14);
	
	EXPECT_INSTRUCTION_BY_OFFSET(0x11,
		BitOffset(0x11, 0),
		5,
		".byte   0x15",
		0x15);
}

class CodeAnalyserFenceTest: public ::testing::Test
{
	public:
		SharedDocumentPointer doc;
		std::unique_ptr<CodeAnalyser> analyser;
		
		CodeAnalyserFenceTest():
			doc(SharedDocumentPointer::make())
		{
			const unsigned char DATA[] = {
				0x90, 0x90, 0x90, 0x90,
				0x90, 0x90, 0x90, 0x90,
				0x90, 0x90, 0x90, 0x90,
				0x90, 0x90, 0x90, 0x90,
				
				0x83, 0xC4, 0x04, 0x90, /* 83C404 = add esp, 4 */
				0x83, 0xEB, 0x05, 0x90, /* 83EB05 = sub ebx, 5
				                         *   EB05 = jmp 0x1c */
				
				0x90, 0x90, 0x90, 0x90,
				0x90, 0x90, 0x90, 0x90,
			};
			
			doc->insert_data(0, DATA, sizeof(DATA));
			
			/* Create CodeAnalyser covering our test data */
			analyser.reset(new CodeAnalyser(doc, 12, 16, CS_ARCH_X86, CS_MODE_32));
		}
		
		void wait()
		{
			while(analyser->get_analysis_position().offset < 28)
			{
				std::this_thread::sleep_for(std::chrono::milliseconds(10));
			}
		}
		
		std::string disassemble()
		{
			std::string disassembly;
			
			for(int i = 0;; ++i)
			{
				CodeAnalyser::Instruction instr = analyser->instruction_by_line(12, i);
				if(instr)
				{
					char s[256];
					snprintf(s, sizeof(s), "%04X    %s\n", (unsigned)(instr.offset().byte()), instr.assembly().c_str());
					
					disassembly += s;
				}
				else{
					break;
				}
			}
			
			return disassembly;
		}
};

TEST_F(CodeAnalyserFenceTest, FenceForZeroLengthComments)
{
	wait();
	
	EXPECT_EQ(analyser->accumulate_fences(), std::vector<off_t>({}));
	
	EXPECT_EQ(disassemble(),
		"000C    nop     \n"
		"000D    nop     \n"
		"000E    nop     \n"
		"000F    nop     \n"
		"0010    add     esp, 4\n"
		"0013    nop     \n"
		"0014    sub     ebx, 5\n"
		"0017    nop     \n"
		"0018    nop     \n"
		"0019    nop     \n"
		"001A    nop     \n"
		"001B    nop     \n");
	
	doc->set_comment(12, 0, Document::Comment("Comment 1"));
	doc->set_comment(13, 0, Document::Comment("Comment 2"));
	doc->set_comment(21, 0, Document::Comment("Comment 3"));
	doc->set_comment(27, 0, Document::Comment("Comment 4"));
	doc->set_comment(28, 0, Document::Comment("Comment 5"));
	
	wait();
	
	EXPECT_EQ(analyser->accumulate_fences(), std::vector<off_t>({ 1, 9, 15 }));
	
	EXPECT_EQ(disassemble(),
		"000C    nop     \n"
		"000D    nop     \n"
		"000E    nop     \n"
		"000F    nop     \n"
		"0010    add     esp, 4\n"
		"0013    nop     \n"
		"0014    .byte   0x83\n"
		"0015    jmp     0x1c\n"
		"0017    nop     \n"
		"0018    nop     \n"
		"0019    nop     \n"
		"001A    nop     \n"
		"001B    nop     \n");
}

TEST_F(CodeAnalyserFenceTest, FencesForNonzeroLengthComments)
{
	wait();
	
	EXPECT_EQ(analyser->accumulate_fences(), std::vector<off_t>({}));
	
	EXPECT_EQ(disassemble(),
		"000C    nop     \n"
		"000D    nop     \n"
		"000E    nop     \n"
		"000F    nop     \n"
		"0010    add     esp, 4\n"
		"0013    nop     \n"
		"0014    sub     ebx, 5\n"
		"0017    nop     \n"
		"0018    nop     \n"
		"0019    nop     \n"
		"001A    nop     \n"
		"001B    nop     \n");
	
	doc->set_comment(16, 5, Document::Comment("Comment 1"));
	doc->set_comment(24, 2, Document::Comment("Comment 2"));
	
	wait();
	
	EXPECT_EQ(analyser->accumulate_fences(), std::vector<off_t>({ 4, 9, 12, 14 }));
	
	EXPECT_EQ(disassemble(),
		"000C    nop     \n"
		"000D    nop     \n"
		"000E    nop     \n"
		"000F    nop     \n"
		"0010    add     esp, 4\n"
		"0013    nop     \n"
		"0014    .byte   0x83\n"
		"0015    jmp     0x1c\n"
		"0017    nop     \n"
		"0018    nop     \n"
		"0019    nop     \n"
		"001A    nop     \n"
		"001B    nop     \n");
}

TEST_F(CodeAnalyserFenceTest, FencesForNestedComments)
{
	wait();
	
	EXPECT_EQ(analyser->accumulate_fences(), std::vector<off_t>({}));
	
	EXPECT_EQ(disassemble(),
		"000C    nop     \n"
		"000D    nop     \n"
		"000E    nop     \n"
		"000F    nop     \n"
		"0010    add     esp, 4\n"
		"0013    nop     \n"
		"0014    sub     ebx, 5\n"
		"0017    nop     \n"
		"0018    nop     \n"
		"0019    nop     \n"
		"001A    nop     \n"
		"001B    nop     \n");
	
	doc->set_comment( 2, 28, Document::Comment("Comment 1"));
	doc->set_comment(14, 10, Document::Comment("Comment 1.1"));
	doc->set_comment(14,  0, Document::Comment("Comment 1.1.0"));
	doc->set_comment(16,  5, Document::Comment("Comment 1.1.1"));
	doc->set_comment(24,  2, Document::Comment("Comment 1.2"));
	doc->set_comment(24,  0, Document::Comment("Comment 1.2"));
	
	wait();
	
	EXPECT_EQ(analyser->accumulate_fences(), std::vector<off_t>({ 2, 4, 9, 12, 14 }));
	
	EXPECT_EQ(disassemble(),
		"000C    nop     \n"
		"000D    nop     \n"
		"000E    nop     \n"
		"000F    nop     \n"
		"0010    add     esp, 4\n"
		"0013    nop     \n"
		"0014    .byte   0x83\n"
		"0015    jmp     0x1c\n"
		"0017    nop     \n"
		"0018    nop     \n"
		"0019    nop     \n"
		"001A    nop     \n"
		"001B    nop     \n");
}
