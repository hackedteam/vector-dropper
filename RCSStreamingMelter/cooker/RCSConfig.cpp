#include <string>
using namespace std;

#include <boost/filesystem/fstream.hpp>

#include <boost/program_options.hpp>
namespace po = boost::program_options;

#include "common.h"
#include "RCSConfig.h"

RCSConfig::RCSConfig(bf::path directory, std::string inifile)
: basedir_(directory), ini_(inifile)
{
	bf::path ini = basedir_ / ini_;
	
	po::variables_map rcs_vm;
	po::options_description rcs_desc("RCS.ini options");
	rcs_desc.add_options()
		("RCS.VERSION", po::value< string >(), "VERSION")	
		("RCS.HUID", po::value< string >(), "HUID")
		("RCS.HCORE", po::value< string >(), "HCORE")
		("RCS.DLL64", po::value< string >(), "DLL64")
		("RCS.HCONF", po::value< string >(), "HCONF")
		("RCS.HDRV", po::value< string >(), "HDRV")
		("RCS.DRIVER64", po::value< string >(), "DRIVER64")
		("RCS.CODEC", po::value< string >(), "CODEC")
		("RCS.HDIR", po::value< string >(), "HDIR")
		("RCS.MANIFEST", po::value< string >(), "MANIFEST")
		("RCS.HREG", po::value< string >(), "HREG")
		("RCS.HSYS", po::value< string >(), "HSYS")
		("RCS.HKEY", po::value< string >(), "HKEY")
		("RCS.FUNC", po::value< string >(), "FUNC")
		;
	
	bf::ifstream conf_file(ini);
	po::store( po::parse_config_file(conf_file, rcs_desc), rcs_vm );
	po::notify(rcs_vm);

	uid_ = rcs_vm["RCS.HUID"].as<string>();
	
	std::string core = rcs_vm["RCS.HCORE"].as<string>();
	core_ = basedir_ / core;
	if ( ! bf::exists(core_))
		throw FileNotFound(core_);

	// core64 is optional
	if (rcs_vm.count("RCS.DLL64")) {
		std::string core64 = rcs_vm["RCS.DLL64"].as<string>();
		core64_ = basedir_ / core64;
		if ( !bf::exists(core64_))
			throw FileNotFound(core64_);
	}
	
	std::string config = rcs_vm["RCS.HCONF"].as<string>();
	config_ = basedir_ / config;
	if ( ! bf::exists(config_))
		throw FileNotFound(config_);
	
	// driver is optional
	if (rcs_vm.count("RCS.HDRV")) {
		std::string driver = rcs_vm["RCS.HDRV"].as<string>();
		driver_ = basedir_ / driver;
		if ( ! bf::exists(driver_))
			throw FileNotFound(driver_);
	}

	// driver64 is optional
	if (rcs_vm.count("RCS.DRIVER64")) {
		std::string driver64 = rcs_vm["RCS.DRIVER64"].as<string>();
		driver64_ = basedir_ / driver64;
		if ( !bf::exists(driver64_))
			throw FileNotFound(driver64_);
	}
	
	// codec is optional
	if (rcs_vm.count("RCS.CODEC")) {
		std::string codec = rcs_vm["RCS.CODEC"].as<string>();
		codec_ = basedir_ / codec;
		if ( ! bf::exists(codec_))
			throw FileNotFound(codec_);
	}
	
	directory_ = rcs_vm["RCS.HDIR"].as<string>();
	manifest_ = rcs_vm["RCS.MANIFEST"].as<string>().compare("yes") ? false : true;
	func_ = rcs_vm["RCS.FUNC"].as<string>();
}
