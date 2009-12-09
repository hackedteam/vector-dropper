/*
 * DataBuffer.cpp
 *
 *  Created on: Jan 19, 2009
 *      Author: daniele
 */

#include <iostream>

using namespace std;

#include "Chunk.h"
#include "FileBuffer.h"

Chunk::Chunk(std::size_t start, RawBuffer* buffer)
: start(start), offset(0), buffer(buffer)
{
}

Chunk::Chunk(const Chunk& c)
: start(c.start), offset(c.offset), buffer(c.buffer)
{
}

Chunk::~Chunk()
{
}

void Chunk::append(char const * const data, std::size_t length)
{
  cout << "Appending " << length << " bytes to chunk." << endl;
  
	buffer->write(data, length, start + offset);
	offset += length;
}
