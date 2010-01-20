#ifndef _MANIFEST_H
#define _MANIFEST_H

#include <string>
using namespace std;

#include <xercesc/dom/DOM.hpp>
#include <xercesc/dom/DOMDocument.hpp>
using namespace xercesc;

class Manifest
{
private:
	string _manifest;
	DOMImplementation* _impl;
	DOMLSParser* _parser;
	xercesc::DOMDocument *_doc;
	
	DOMElement* createTrustInfo();
	
public:
	Manifest();
	Manifest(string manifest);
	virtual ~Manifest(void);
	
	void create();
	bool check();
	bool serialize();
	
	string toString() { return _manifest; }
	char const * toCharPtr() { return _manifest.c_str(); }
	size_t size() { return _manifest.size(); }
	
	static bool initialize();
};

#endif /* _MANIFEST_H */
