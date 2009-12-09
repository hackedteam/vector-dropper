#ifndef _EXCEPTIONS_H
#define _EXCEPTIONS_H

#include <exception>

class InvalidResourcesException : public std::exception
{
public:
	virtual const char* what() const throw()
	{
		return "INVALID RESOURCES";
	}
};

class InvalidPEException : public std::exception
{
public:
	virtual const char* what() const throw()
	{
		return "INVALID PE FILE";
	}
};

#endif /* _EXCEPTIONS_H */