#include "../BitOffset.hpp"
#include "../ByteRangeSet.hpp"

class %delete REHex::BitOffset
{
	REHex::BitOffset();
	REHex::BitOffset(off_t byte, int bit);
	
	off_t byte() const;
	int bit() const;
	off_t total_bits();
	bool byte_aligned() const;
	off_t byte_round_up() const;
	
	bool operator<(const REHex::BitOffset &rhs) const;
	bool operator<=(const REHex::BitOffset &rhs) const;
	bool operator==(const REHex::BitOffset &rhs) const;
	
	REHex::BitOffset operator+(const REHex::BitOffset &rhs) const;
	REHex::BitOffset operator-(const REHex::BitOffset &rhs) const;
	
	// BitOffset operator%(const BitOffset &rhs) const;
	
	REHex::BitOffset operator-() const;
};

class %delete REHex::ByteRangeSet
{
	REHex::ByteRangeSet();

	void set_range(off_t offset, off_t length);
	void clear_range(off_t offset, off_t length);
	void set_ranges(const REHex::ByteRangeSet &set);
	void clear_ranges(const REHex::ByteRangeSet &set);
	void clear_all();

	bool isset(off_t offset, off_t length = 1);
	bool isset_any(off_t offset, off_t length);
	
	LuaTable get_ranges() const;
};
