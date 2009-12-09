/*
 * DataBuffer.h
 *
 *  Created on: Jan 19, 2009
 *      Author: daniele
 */

#ifndef _CHUNK_H
#define _CHUNK_H

#include <cstddef>
#include <string>

class RawBuffer;

class Chunk {
public:
	Chunk(std::size_t start, RawBuffer* buffer);
	Chunk(const Chunk& c);
	virtual ~Chunk();
	
	std::size_t get_start() { return start; }
	std::size_t get_offset() { return offset; }
	void set_offset(std::size_t offset) { this->offset = offset; }
	
	void append(char const * const data, std::size_t length);
	
	bool operator < (const Chunk& rhs)
	{
		return start < rhs.start;
	}
	
	Chunk & operator = (const Chunk & rhs)
	{
		if (this == &rhs)
			return *this;

		start = rhs.start;
		offset = rhs.offset;
		buffer = rhs.buffer;
	}

	bool operator== (const Chunk& rhs) {
		return (start == rhs.start && offset == rhs.offset && buffer == rhs.buffer);
	}

	bool operator/ (const Chunk& rhs) {
		std::size_t rhs_start = const_cast<Chunk&>(rhs).get_start();
		// std::size_t rhs_end = rhs_start + const_cast<Chunk&>(rhs).get_offset();
		std::size_t end = start + offset;

		if ((signed int)(rhs_start - end) <= 0)
		{
			return true;
		}

		return false;
	}

private:
	std::size_t start;
	std::size_t offset;

	RawBuffer* buffer;
};

#endif /* _CHUNK_H */
