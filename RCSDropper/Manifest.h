#ifndef _MANIFEST_H
#define _MANIFEST_H

#include <string>
using namespace std;

class Manifest
{
private:
	string _manifest;
	
public:
	Manifest();
	Manifest(string manifest);
	virtual ~Manifest(void);
	
	void Create();
	bool AddSecurityInfo();
	
	string toString() { return _manifest; }
	char const * toCharPtr() { return _manifest.c_str(); }
	size_t size() { return _manifest.size(); }
};

#endif /* _MANIFEST_H */
