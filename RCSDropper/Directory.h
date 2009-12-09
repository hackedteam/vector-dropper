#ifndef _DIRECTORY_H
#define _DIRECTORY_H

#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/convenience.hpp>
namespace bf = boost::filesystem;

class Directory
{
private:
	bf::path _path;
	
public:
	Directory(bf::path path) : _path(path) {}
	~Directory() {}
	
	bool exists() { return bf::exists(_path); }
	bool create() 
	{ 
		try { 
			bf::create_directories(_path); 
		} catch (bf::filesystem_error e) {
			return false;
		}

		return true;
	};
};

#endif /* _DIRECTORY_H */