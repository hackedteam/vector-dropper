#ifndef IATEntry_h__
#define IATEntry_h__

#include <sstream>
#include <iostream>
#include <string>

class IATEntry
{
private:
	std::string _dll;
	std::string _call;
	unsigned int _index;
public:
	IATEntry(std::string dll, std::string call, unsigned int index)
		: _dll(dll), _call(call), _index(index)
	{
		// std::cout << "IATEntry: " << _dll << ".(" << _call << ") @" << _index << std::endl;
	}
	
	std::string dll() const { return _dll; }
	std::string call() const { return _call; }
	unsigned int index() const { return _index; }
	
	static std::string str(IATEntry const & entry)
	{ 
		std::ostringstream s; 
		s << entry.dll() << ".(" << entry.call()<< ")";
		return s.str();
	}
};

typedef std::map< std::size_t, IATEntry > IATEntries;

class IATEntryNotFound : public std::exception 
{
public:
	IATEntryNotFound( const string& msg = "" ) : std::exception(msg.c_str()) {}
};

#endif // IATEntry_h__
