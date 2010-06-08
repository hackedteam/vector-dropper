#if 0
#include <ctime>
#include <iostream>
#include <string>
#include <ctime>
using namespace std;

#include <boost/shared_array.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
namespace bf = boost::filesystem;

#include <Windows.h>

#include "Chunk.h"
#include "StreamingMelter.h"

int main(int argc, char* argv[])
{
#if 0
	char a[1000];
		
	while (1)
	{
		Chunk x(a, 10);
		Chunk y = x /5;
		Chunk z = x + y;
		Chunk w = z;
		cout << "X " << x.size() << ", Y: " << y.size() << ", Z: " << z.size() << ", W: " << w.size() << endl;
	}
#endif
	
	bf::path program(argv[0]);
	
	if (argc < 3) {
		cout << "Usage: " << program.leaf() << " <input> <output>" << endl;
		return -1;
	}
	
	bf::path input(argv[1], bf::native);
	bf::path output(argv[2], bf::native);
	
	if (!bf::exists(input)) {
		cout << "File " << input.leaf() << " does not exists." << endl;
		return -2;
	}
	
	cout << "[INPUT] File " << input << endl;
	
	bf::fstream input_file;
	input_file.open(input, ios::in | ios::binary);
	if (!input_file.is_open()) {
		cout << "ERROR opening file: " << input << endl;
		return -1;
	}

	bf::fstream output_file;
	output_file.open(output, ios::out | ios::binary);
	if (!output_file.is_open()) {
		cout << "ERROR opening file: " << output << endl;
		return -1;
	}
	
	StreamingMelter melter;
	melter.initiate();
	
	srand( (unsigned int) time(NULL) );
	
	while ( ! input_file.eof() && ! melter.done() ) {
		std::size_t s = rand() % 1000; 
		boost::shared_array<char> buf(new char[s]);
		
		cout << "[INPUT] reading " << s << " bytes." << endl;
		
		input_file.read(buf.get(), s);
		if (input_file.fail())
			s = input_file.gcount();
		
		melter.feed(buf.get(), s);
		boost::shared_ptr<Chunk> chunk = melter.output();
		output_file.write(chunk->data(), chunk->size());
	}
	
	input_file.close();
	output_file.close();
	
	return 0;
}
#endif
