#ifndef _CHUNK_H
#define _CHUNK_H

#include <cstring>
#include <boost/shared_ptr.hpp>
#include <boost/shared_array.hpp>

class Chunk;
typedef boost::shared_ptr<Chunk> ChunkPtr;

#if 0
Chunk merge(Chunk& a, Chunk& b)
{

}

Chunk split(Chunk& a, std::size_t size)
{

}
#endif

class Chunk {
public:
	Chunk()
		: size_(0)
	{
		data_.reset(NULL);
	}
	
	Chunk(const Chunk& rhs)
	{
		size_ = rhs.size_;
		data_.reset(new char[size_]);
		std::memcpy(data_.get(), rhs.data_.get(), size_);
	}
	
	Chunk(const char * const data, std::size_t size)
		: size_(size)
	{
		data_.reset( new char[size_] );
		if (data)
			memcpy(data_.get(), data, size_);
	}
	
	Chunk& operator=(const Chunk& rhs)
	{	
		if (this == &rhs)
			return *this;
		
		char* tmp = new char[rhs.size_];
		memcpy(tmp, rhs.data_.get(), rhs.size_);
		data_.reset( tmp );
		size_ = rhs.size_;
		
		return *this;
	}
	
	Chunk& operator+=(const Chunk& rhs)
	{
		char* tmp = new char[size_ + rhs.size_];
		memcpy(tmp, data_.get(), size_);
		memcpy(tmp + size_, rhs.data_.get(), rhs.size_);
		data_.reset( tmp );
		size_ += rhs.size_;
		return *this;
	}
	
	Chunk operator+(const Chunk& rhs)
	{
		return Chunk(*this) += rhs;
	}
	
	bool operator==(const Chunk& rhs) 
	{
		if (this == &rhs)
			return true;

		if (this->size() == rhs.size_ && ! memcmp(data_.get(), rhs.data_.get(), rhs.size_) )
			return true;

		return false;
	}
	
	bool operator!=(const Chunk& rhs)
	{
		return !(*this == rhs);
	}
	
	Chunk operator/(size_t size)
	{
		if (size > size_)
			return Chunk(NULL, 0);
		
		Chunk result(data_.get(), size);
		Chunk tmp (data_.get() + size, size_ - size);
		*this = tmp;
		
		return result;
	}
	
	void discard(std::size_t size)
	{
		*this / size;
	}

	char * const_data() const { return data_.get(); }
	char * data() { return data_.get(); }
	std::size_t size() const { return size_; }

private:
	boost::shared_array<char> data_;
	std::size_t size_;
};

#endif /* _CHUNK_H */
