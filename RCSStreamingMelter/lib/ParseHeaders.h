/*
 * ParseDOSHeader.h
 *
 *  Created on: Apr 27, 2010
 *      Author: daniele
 */

#ifndef PARSEDOSHEADER_H_
#define PARSEDOSHEADER_H_

struct ParseHeaders : DataState< ParseHeaders, Parsing >
{
public:
	void init();
	StateResult parse();
	StateResult process();
	sc::result transitToNext();

	ParseHeaders();
	~ParseHeaders();
private:

	bool parseHTTPHeaders();
	bool parseDOSHeader();
	bool parseNTHeaders();
	bool parseSectionHeaders();

	void sendHTTPHeaders(std::size_t sizeOfImageSkew);

	std::vector< std::string > httpHeaders_;
	std::size_t httpHeadersSize_;
	PIMAGE_DOS_HEADER dosHeader_;
	PIMAGE_NT_HEADERS ntHeaders_;
	std::size_t firstSectionDataOffset_;
};

#endif /* PARSEDOSHEADER_H_ */
