#ifndef _MELTFILE_H
#define _MELTFILE_H

#include <string>
using namespace std;

#include <boost/filesystem.hpp>
namespace bf = boost::filesystem;

typedef struct _melter_struct {
	CHAR core[MAX_PATH];
	CHAR conf[MAX_PATH];
	CHAR driver[MAX_PATH];
	CHAR codec[MAX_PATH];
	CHAR instdir[MAX_PATH];
	BOOL manifest;
} MelterStruct, *pMelterStruct;

extern "C" int __declspec(dllexport) MeltFile( char const * const input_path, char const * const output_path, MelterStruct const * const melter_data );

#endif /* _MELTFILE_H */
