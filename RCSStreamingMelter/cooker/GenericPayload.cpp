#include <iostream>
#include <string>

#include "GenericPayload.h"
#include "Components.h"

GenericPayload::GenericPayload(bf::path payload_path, Components& components)
: payload_path_(payload_path), components_(components)
{
}

GenericPayload::~GenericPayload(void)
{
}

bool GenericPayload::write( bf::path file )
{
	std::cout << "Writing file : " << file << std::endl;
	
	return true;
}
