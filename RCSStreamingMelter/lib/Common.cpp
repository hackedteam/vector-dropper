/*
 * Common.cpp
 *
 *  Created on: May 4, 2010
 *      Author: daniele
 */

#include "Common.h"

#include <iostream>
#include <sstream>

#include <boost/regex.hpp>
#include <string>

std::string parseFunctionName(std::string text)
{
	// void DataState<Derived, Outer>::preamble() [with Derived = ParseDOSHeader, Outer = Parsing]

	// virtual boost::statechart::result Defective::react(const EvNewData&)
	// virtual void ParseNTHeader::parse()
	const boost::regex templated("^\\w* \\w*<\\w*, \\w*>::(\\w*)\\(\\) \\[with \\w* = (\\w*),.*");
	const boost::regex plain("^(virtual)?\\s?\\w*(::\\w*::\\w*)?\\s?(\\w*)::(\\w*).*");
	boost::cmatch what;

	std::string className = "unknown";
	std::string functionName = "unknown";

	if ( boost::regex_match(text.c_str(), what, templated) ) {
#if 0
		std::cout << "$1 = " << what[1].str() << std::endl;
		std::cout << "$2 = " << what[2].str() << std::endl;
#endif
		className = what[2].str();
		functionName = what[1].str();
	} if ( boost::regex_match(text.c_str(), what, plain) ) {
#if 0
		std::cout << "$1 = " << what[1].str() << std::endl;
		std::cout << "$2 = " << what[2].str() << std::endl;
		std::cout << "$3 = " << what[3].str() << std::endl;
		std::cout << "$4 = " << what[4].str() << std::endl;
#endif
		if ( ! what[3].str().empty())
			className = what[3].str();
		else
			className = what[2].str();
		functionName = what[4].str();
	}

	std::ostringstream ss;
	ss << className << "::" << functionName;
	return ss.str();
}

void debugTrace(std::string filename, unsigned int line, std::string function, std::string msg, std::string par)
{
	(void) filename;
	std::ostringstream ss;
	bf::path f = __FILE__;
	std::string funcPrototype = parseFunctionName( function );
	ss << "[" << funcPrototype << " @ " << line << "] " << msg << " " << par;

	std::cout << ss.str() << std::endl;
}
