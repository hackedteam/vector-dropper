#pragma once

#include <boost/filesystem.hpp>
namespace bf = boost::filesystem;

class Components;

class GenericPayload
{
public:
	GenericPayload(bf::path payload_path, Components& components);
	~GenericPayload(void);

	bool write(bf::path file);

private:
	bf::path payload_path_;
	Components& components_;
};
