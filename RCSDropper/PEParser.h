#ifndef _PEPARSER_H
#define _PEPARSER_H

#include <iostream>
#include <map>
#include <string>
#include <utility>
using namespace std;

#include <boost/function.hpp>
#include <boost/scoped_array.hpp>

typedef std::pair<size_t, size_t> chunkID;

class PEParser;

typedef boost::function<bool (PEParser*, chunkID)> action;
typedef std::multimap< chunkID, action > action_map;

class PEParser {
protected:
	int _id;
	
	size_t _offset;
	size_t _size;
	
	boost::scoped_array<char> _buffer;
	
	action_map _actions;
	action_map::iterator _currentAction;
	
	void _addAction(std::pair<size_t, size_t> p, action a) 
	{
		_actions.insert( make_pair( p, a ) );
	}
	
	void _print() {
		for (action_map::iterator iter = _actions.begin(); 
			iter != _actions.end();
			iter++)
		{
			std::pair<size_t, size_t> a = (*iter).first;
			cout << "ACTION a = " << a.first << ", b = " << a.second << endl;
		}
	}
	
	size_t chunk_size( chunkID c ) { return c.second; }
	size_t chunk_offset( chunkID c ) { return c.first; }
	
public:
	
	PEParser(int id) : _id(id) 
	{
		_addAction( make_pair(10, 10), &PEParser::parse_DOSHeader);
		_currentAction = _actions.begin();
	}
	
	bool parse_DOSHeader( chunkID chunk ) {
		size_t offset = chunk_offset(chunk);
		size_t size = chunk_size(chunk);
		
		cout << "[" << _id << "] method1 called with a = " << offset << ", b = " << size << endl;
		_addAction( make_pair(offset+10, size+10), &PEParser::parse_NTHeader);
		_addAction( make_pair(offset+10, size+10), &PEParser::parse_Section);
		return true;
	}
	
	bool parse_NTHeader( chunkID chunk ) {
		size_t offset = chunk_offset(chunk);
		size_t size = chunk_size(chunk);
		
		cout << "[" << _id << "] method2 called with a = " << offset << ", b = " << size << endl;
		_addAction( make_pair(offset+10, size+10), &PEParser::parse_Section);
		return true;
	}
	
	bool parse_Section( chunkID chunk ) {
		size_t offset = chunk_offset(chunk);
		size_t size = chunk_size(chunk);

		cout << "[" << _id << "] method3 called with a = " << offset << ", b = " << size << endl;
		// _addAction( make_pair(offset+10, size+10), &TestClass::method1);
		return true;
	}
	
	void parse()
	{
		while ( _currentAction != _actions.end())
		{
			action a;
			
			chunkID p = (*_currentAction).first;
			a = (*_currentAction).second;
			
			if (_offset >= chunk_offset(p) && _size >= chunk_size(p))
			{
				if ( a(this, p) == true) {
					action_map::iterator tmp;
					tmp = _currentAction;
					_currentAction++;
					_actions.erase(tmp);
				} else {
					_currentAction++;
				}
				
				_print();

			} else {
				return;
			}
		}
	}
	
	void feed(char* data, size_t offset, size_t size)
	{
		_offset = offset;
		_size = size;
		
		// parse();
	}
};

#endif /* _PEPARSER_H */