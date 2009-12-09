/*
 * DataBuffer.h
 *
 *  Created on: Jan 19, 2009
 *      Author: daniele
 */

#ifndef _FILEBUFFER_H
#define _FILEBUFFER_H

#include <list>
#include <map>
#include <string>
#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/iostreams/device/mapped_file.hpp>
#include <iostream>
namespace bf = boost::filesystem;
namespace bio =  boost::iostreams;

#include "Buffer.h"
#include "Chunk.h"
#include "Directory.h"

// TODO refactor

class RawBuffer : public DataBuffer, ChunkedBuffer {
public:
	RawBuffer(bf::path filepath);
	virtual ~RawBuffer();
	
	bool open();
	bool create(size_t bytes);
	void close() { _close(); }
	size_t size() { return bf::file_size(_path); }
	
	char* data() { return filemap.data(); }
	char const * const const_data() { return filemap.const_data(); }

	void add_chunk(std::string id, std::size_t start);
	Chunk* const get_chunk(std::string id) { return chunks[id]; }
	
	bool is_complete(std::size_t offset, std::size_t length);
	
	bf::path path() { return _path; }
	
private:
	bf::path _path;

	bool _init();
	bool _open();
	bool _create();
	bool _zeroFill(size_t bytes);
	bool _mapInMemory();
	void _close() { file.close(); }

	Directory* _basepath;
	
	bf::fstream file;
	bio::mapped_file filemap;
	
	std::map<std::string, Chunk*> chunks;
};

#endif /* _FILEBUFFER_H */
