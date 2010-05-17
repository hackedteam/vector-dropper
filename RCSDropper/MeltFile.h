#ifndef _MELTFILE_H
#define _MELTFILE_H

#include <exception>
#include <string>
using namespace std;

#include <boost/filesystem.hpp>
namespace bf = boost::filesystem;

typedef struct _melter_struct {
	CHAR core[MAX_PATH];
	CHAR core64[MAX_PATH];
	CHAR conf[MAX_PATH];
	CHAR driver[MAX_PATH];
	CHAR driver64[MAX_PATH];
	CHAR codec[MAX_PATH];
	CHAR instdir[MAX_PATH];
	bool manifest;
} MelterStruct, *pMelterStruct;

class melting_error : public std::exception {
private:
	std::string _err;
public:
	melting_error( const string &err ) : _err(err) {}
	char const * what() { return _err.c_str(); }
};

int __declspec(dllexport) MeltFile( 
	char const * const input_path, 
	char const * const output_path, 
	MelterStruct const * const melter_data ) throw(...);

#endif /* _MELTFILE_H */
