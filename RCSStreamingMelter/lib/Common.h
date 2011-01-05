#ifndef Common_h__
#define Common_h__

#include <iomanip>
#include <iostream>
#include <sstream>

#include <boost/filesystem.hpp>
#include <boost/filesystem/path.hpp>
namespace bf = boost::filesystem;

#include "../MelterConfig.h"

#ifdef WIN32
#include <Windows.h>
#else
#include "win32types.h"
#endif

#include "debug.h"

typedef void (*debug_msg_t)(char level, const char* message, ...);

#ifdef __cplusplus
extern "C" {
#endif
debug_msg_t debug_fn();
#ifdef __cplusplus
}
#endif

void set_debug_fn( debug_msg_t fn );

#define DBG_MINPRIO D_VERBOSE

#ifdef WIN32
#define __PRETTY_FUNCTION__ __FUNCTION__
#endif

void debugTrace_extended(std::string filename, unsigned int line, std::string function, std::string msg, std::string par);
void debugTrace(char level, const char* message, ...);

#ifdef _DEBUG

#define DBGTRACE(msg, par, pri) do { \
		if ( (unsigned int)pri >= (unsigned int)DBG_MINPRIO ) \
		{ \
			std::ostringstream spar; \
			spar << (par); \
			debugTrace_extended(__FILE__, __LINE__, __PRETTY_FUNCTION__, msg, spar.str()); \
		} \
	} while(0)

#define DBGTRACE_HEX(msg, par, pri) do { \
		if ( (unsigned int)pri >= (unsigned int)DBG_MINPRIO ) \
		{ \
			std::ostringstream spar; \
			spar << "0x" << hex << (par); \
			debugTrace_extended(__FILE__, __LINE__, __PRETTY_FUNCTION__, msg, spar.str()); \
		} \
	} while (0)

#define DBGTRACE_BUFFER(pri) do { \
		if ( (unsigned int)pri >= (unsigned int)DBG_MINPRIO ) { \
		std::ostringstream spar; \
		spar << "[ " << ( done() ? "true" : "false" ) << hex \
					<< " trig: " << triggeringOffset() \
		            << " curr: " << currentOffset() \
		            << " need: " << neededBytes() \
		            << " aval: " << availableOffset() \
		            << " ]"; \
		debugTrace_extended(__FILE__, __LINE__, __PRETTY_FUNCTION__, spar.str(), ""); \
		} \
	} while (0)

#else
#define DBGTRACE(msg, par, pri)
#define DBGTRACE_HEX(msg, par, pri)
#define DBGTRACE_BUFFER(pri)
#endif

#endif // Common_h__
