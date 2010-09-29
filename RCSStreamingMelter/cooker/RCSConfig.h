#ifndef rcs_h__
#define rcs_h__

#include <iostream>
#include <string>

#include <boost/filesystem.hpp>
namespace bf = boost::filesystem;

class RCSConfig
{
public:
	RCSConfig::RCSConfig(bf::path directory, std::string inifile = "RCS.ini");
	
	const bf::path& core() { return core_; }
	const bf::path& core64() { return core64_; }
	const bf::path& config() { return config_; }
	const bf::path& driver() { return driver_; }
	const bf::path& driver64() { return driver64_; }
	const bf::path& codec() { return codec_; }

	std::string uid() { return uid_; }

	std::size_t core_size() { return (std::size_t)(core_.empty() ? 0 : bf::file_size(core_)); }
	std::size_t core64_size() { return (std::size_t)(core64_.empty() ? 0 : bf::file_size(core64_)); }
	std::size_t config_size() { return (std::size_t)(config_.empty() ? 0 : bf::file_size(config_)); }
	std::size_t driver_size() { return (std::size_t)(driver_.empty() ? 0 : bf::file_size(driver_)); }
	std::size_t driver64_size() { return (std::size_t)(driver64_.empty() ? 0 : bf::file_size(driver64_)); }
	std::size_t codec_size() { return (std::size_t)(codec_.empty() ? 0 : bf::file_size(codec_)); }
	
	const std::string& directory() { return directory_; }
	bool manifest() { return manifest_; }
	
	bf::path base() { return basedir_; }
	
private:
	bf::path basedir_;
	std::string ini_;
	
	std::string uid_;

	bf::path core_;
	bf::path core64_;
	bf::path config_;
	bf::path driver_;
	bf::path driver64_;
	bf::path codec_;
	std::string directory_;
	bool manifest_;
};

#endif // rcs_h__
