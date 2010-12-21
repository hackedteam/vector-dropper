/*
 * DataBuffer.cpp
 *
 *  Created on: Jan 19, 2009
 *      Author: daniele
 */

#include <iostream>
#include <algorithm>
using namespace std;

#include "Chunk.h"
#include "FileBuffer.h"

RawBuffer::RawBuffer(bf::path filepath)
: _path(filepath)
{
}

RawBuffer::~RawBuffer()
{
	// filemap.close();
	file.close();
}

void RawBuffer::add_chunk(std::string id, std::size_t start)
{
	Chunk* chunk = new Chunk(start, this);
	chunks[id] = chunk;
}

bool RawBuffer::is_complete(std::size_t start, std::size_t length)
{
	// copy chunks to list, and sort it by start offset
	std::list<Chunk> chunk_list;
	std::map<std::string, Chunk*>::iterator map_iter;
	for (map_iter = chunks.begin(); map_iter != chunks.end(); map_iter++)
		chunk_list.push_back(*((*map_iter).second));
	chunk_list.sort();

	// check if requested chunk is present
	std::list<Chunk>::iterator iter = chunk_list.begin();
	while (iter != chunk_list.end())
	{
		std::size_t cstart = (*iter).get_start();
		std::size_t cend = (*iter).get_start() + (*iter).get_offset();

		// std::printf("%ld <= %ld <= %ld (%s)\n", cstart, start, cend, (cstart <= start && start <= cend) ? "true" : "false");
   		if (cstart <= start && start <= cend) {
			// requested chunk begins here

			// std::printf("%ld + %ld <= %ld (%s)\n", start, length, cend, start + length <= cend ? "true" : "false");
			if (start + length <= cend) {
				// requested chunk ends here
				return true;
			}
			// requested chunk does not end here
			// check in next chunks
			std::list<Chunk>::iterator next = iter;
			while (iter != chunk_list.end())
			{
				next++;
				// check if chunks are contiguous
				if (*iter / *next == false)
					// chunks are not contiguous
					return false;

				// std::printf("Contiguous chunks\n");
				std::size_t cstart = (*next).get_start();
				std::size_t cend = (*next).get_start() + (long)(*next).get_offset();

				// std::printf("%ld + %ld <= %ld (%s)\n", start + length, cend, start + length <= cend ? "true" : "false");
				// check if requested chunk ends here
				if (start + length <= cend) {
					// ends here, we are done! FOUND IT!
					return true;
				}

				// requested chunk does not end here
				iter++;
			}
		}

		// chunk does not begin here, check next
		iter++;
	}

	return false;
}

bool RawBuffer::_open()
{
	// if the file does not exists, we cannot open it :)
	if ( ! exists(_path) )
		return false;

	try {

		// if the file is not already opened, open it beforehand
		if (!file.is_open())
			file.open(_path, std::ios_base::in | std::ios_base::out | std::ios_base::binary);
		else
			return true; // file is already open

		// check if file has been opened
		if (file.is_open() == false)
			return false;
	
	} catch (bf::filesystem_error e) {
		// in case of errors ...
		return false;
	}
	
	return true;
}

bool RawBuffer::_create()
{
	// BEWARE: if a file with the same name already exists, it will be truncated!
	
	try {
		file.open(_path, std::ios_base::in | std::ios_base::out | std::ios_base::binary | std::ios_base::trunc);
		if ( exists(_path) ) 
			return true;
	} catch (bf::filesystem_error e) {
		return false;
	}
	
	return false;
}

bool RawBuffer::_zeroFill( size_t bytes )
{
	// if the file does not exists or has not been opened, we cannot zerofill it ...
	if ( ! exists(_path) || ! file.is_open() )
		return false;

	try {
		char* zero = new char[4096];
		std::memset(zero, 0, 4096);
		
		while (bytes != 0) {
			if (bytes < 4096) {
				file.write(zero, bytes);
				bytes = 0;
			} else {
				file.write(zero, 4096);
				bytes -= 4096;
			}
		}
		
		delete[] zero;
		
	} catch (bf::filesystem_error e) {
		return false;
	}
	
	return true;

}

bool RawBuffer::_mapInMemory()
{
	cout << _path.string() << " size is " << this->size() << endl;
	
	if (file.is_open()) file.close();

	try {
		filemap.open(_path.string(), std::ios_base::in /*| std::ios_base::out*/ | std::ios_base::binary, this->size());
	} catch (bf::filesystem_error e) {
		return false;
	}
	
	return true;
}

bool RawBuffer::_init()
{
	// create the directory if it does not exists
	_basepath = new Directory(_path.branch_path());
	if (_basepath->exists() == false)
		return _basepath->create();

	return true;
}

bool RawBuffer::open()
{
	if (_init() == false) {
		cout << __FUNCTION__ << " failed init." << endl;
		return false;
	}

	if (_open() == false) {
		cout << __FUNCTION__ << " failed open." << endl;	
		return false;
	}

	return _mapInMemory();
}

bool RawBuffer::create( size_t bytes )
{
	if (_init() == false) {
		cout << __FUNCTION__ << " failed init." << endl;
		return false;
	}

	if (_create() == false) {
		cout << __FUNCTION__ << " failed create." << endl;
		return false;
	}

	if (_zeroFill(bytes) == false) {
		cout << __FUNCTION__ << " failed zeroFill." << endl;
		return false;
	}

	return true;
}