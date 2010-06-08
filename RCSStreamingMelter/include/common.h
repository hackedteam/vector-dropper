/*
 * common.h
 *
 *  Created on: Jan 19, 2010
 *      Author: daniele
 */

#ifndef common_h__
#define common_h__

#include <boost/filesystem.hpp>
namespace bf = boost::filesystem;

#ifdef WIN32
#include <Windows.h>
#else
#include "win32types.h"
#endif

inline DWORD alignTo( DWORD _size, DWORD _base_size )
{
	return ( ((_size + _base_size - 1) / _base_size) * _base_size );
}

inline DWORD alignToDWORD( DWORD _size )
{
	return (DWORD)( _size + ( sizeof(DWORD) - (_size % (sizeof(DWORD)))));
}

#define RALIGN(dwToAlign, dwAlignOn) ((dwToAlign%dwAlignOn == 0) ? dwToAlign : dwToAlign - (dwToAlign%dwAlignOn) + dwAlignOn)

class FileNotFound : public std::runtime_error
{
public:
	FileNotFound(std::string filename) : std::runtime_error(filename.c_str()) {}
	FileNotFound(bf::path filepath) : std::runtime_error(filepath.string().c_str()) {}
};

#endif /* common_h__ */
