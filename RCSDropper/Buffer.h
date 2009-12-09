#ifndef _BUFFER_H
#define _BUFFER_H

#include <iostream>

#include "Chunk.h"

class Buffer {
public:
	virtual char const * read(std::size_t offset, std::size_t length) = 0;
	virtual void write(char const * const bytes, std::size_t length, std::size_t offset) = 0;
};

class ChunkedBuffer {
public:
	virtual void add_chunk(std::string id, std::size_t start) = 0;
	virtual Chunk* const get_chunk(std::string id) = 0;
};

class DataBuffer : Buffer {
public:
	virtual char * data() = 0;
	virtual char const * const const_data() = 0;
	
	virtual bool is_complete(std::size_t offset, std::size_t length) = 0;
	
	virtual void write(char const * const bytes, std::size_t length, std::size_t offset)
	{
		std::cout << "Writing " << length << " bytes to memory mapped file @ " << offset << std::endl;
		char* ptr = this->data() + offset;
		std::memcpy(ptr, bytes, length);
	}
	
	virtual char const * read(std::size_t offset, std::size_t length)
	{
		(void) length; // unused
		return this->const_data() + offset;
	}
};

#endif /* _BUFFER_H */