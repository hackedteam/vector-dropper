#ifndef DataCarrier_h__
#define DataCarrier_h__

#include <iostream>
#include <boost/shared_ptr.hpp>

#include "Chunk.h"

struct DataCarrier
{
public:
	DataCarrier(boost::shared_ptr<Chunk> c) { chunk_ = c; }
	DataCarrier(size_t size) : size_(size) {} 

	boost::shared_ptr<Chunk> chunk() const { return chunk_; }

private:
	boost::shared_ptr<Chunk> chunk_;
	std::size_t size_;
};

#endif // DataCarrier_h__
