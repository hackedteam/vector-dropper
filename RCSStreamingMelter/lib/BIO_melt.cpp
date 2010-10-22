#include <iostream>

#include <stdio.h>
#include <errno.h>

#include <boost/filesystem/fstream.hpp>
#include <boost/filesystem.hpp>
namespace bf = boost::filesystem;

#include <openssl/bio.h>
#include <openssl/evp.h>

#include "../include/melt.h"
#include "StreamingMelter.h"

static int injectf_write(BIO *h, const char *buf, int num);
static int injectf_read(BIO *h, char *buf, int size);
static int injectf_puts(BIO *h, const char *str);
static int injectf_gets(BIO *h, char *str, int size);
static long injectf_ctrl(BIO *h, int cmd, long arg1, void *arg2);
static int injectf_new(BIO *h);
static int injectf_free(BIO *data);
static long injectf_callback_ctrl(BIO *h, int cmd, bio_info_cb *fp);

BIO_METHOD method_injectf =
{
	BIO_TYPE_INJECT_FILTER,
	"RCS Inject filter",
	injectf_write,
	injectf_read,
	injectf_puts,
	injectf_gets,
	injectf_ctrl,
	injectf_new,
	injectf_free,
	injectf_callback_ctrl,
};

static int injectf_new(BIO *bi)
{
	try {
		bi->ptr = new StreamingMelter();
	} catch (...) {
		return 0;
	}
	bi->init = 1;
	bi->flags = 0;

	return (1);
}

static int injectf_free(BIO *a)
{
	if (a == NULL)
		return (0);

	delete ( (StreamingMelter*)a->ptr );
	a->init=0;

	return (1);
}
	
static int injectf_read(BIO *b, char *out, int outl)
{
	int ret=0;
 
	if (out == NULL)
		return (0);

	if (b->next_bio == NULL)
		return (0);

	try {
		ret=BIO_read(b->next_bio,out,outl);
	} catch (...) {
		return (0);
	}
	BIO_clear_retry_flags(b);
	BIO_copy_next_retry(b);

	return(ret);
}

static int injectf_write(BIO *b, const char *in, int inl)
{
	int ret = 0;

	if ( (in == NULL) || (inl == 0) )
	   return 0;

	if (b->next_bio == NULL)
		return 0;

	StreamingMelter *sm = (StreamingMelter*) b->ptr;
	if (!sm)
		return 0;

	// write to StreamingMelter, get output and write to next BIO
	try {
		sm->feed(in, inl);
	} catch (...) {
		return 0;
	}

	if ( sm->outputSize() ) {
		ret = BIO_write(b->next_bio, (const void*) sm->output(), sm->outputSize());
		sm->clearOutput();
	}

	BIO_clear_retry_flags(b);
	BIO_copy_next_retry(b);

	return ret;
}

static long injectf_ctrl(BIO *b, int cmd, long num, void *ptr)
{
	long ret;

	// pre BIO_push controls
	switch (cmd) {
	 case BIO_CTRL_SET_DEBUG_FN:
	        {
	        	StreamingMelter *sm = (StreamingMelter*) b->ptr;
	        	if (!sm)
	        		return 0;

	        	std::cout << "Setting DEBUG_FN!" << std::endl;

	        	sm->set_debug_function( (debug_msg_t)ptr );

	        	ret = 0L;
	        }
	        break;
	}

	if (b->next_bio == NULL)
		return 0;

	switch(cmd)
	{
        case BIO_C_DO_STATE_MACHINE:
        	BIO_clear_retry_flags(b);
			ret = BIO_ctrl(b->next_bio,cmd,num,ptr);
			BIO_copy_next_retry(b);
			break;

        case BIO_CTRL_FLUSH:
        {
           StreamingMelter *sm = (StreamingMelter*) b->ptr;
           if (!sm)
              return 0;

           try {
			   sm->feed(NULL, 0);
			   BIO_write(b->next_bio, (const void*) sm->output(), sm->outputSize());
			   sm->clearOutput();
		   } catch (...) {
        	   return 0;
		   }

           ret = BIO_ctrl(b->next_bio,cmd,num,ptr);
        }
        break;

        case BIO_CTRL_DUP:
        	ret = 0L;
        	break;

        default:
        	ret = BIO_ctrl(b->next_bio,cmd,num,ptr);
        	break;
	}

	return(ret);
}

static long injectf_callback_ctrl(BIO *b, int cmd, bio_info_cb *fp)
{
	long ret = 1;

	if (b->next_bio == NULL)
		return(0);

	switch (cmd)
	{
		default:
			ret=BIO_callback_ctrl(b->next_bio,cmd,fp);
			break;
	}

	return(ret);
}

static int injectf_gets(BIO *bp, char *buf, int size)
{
	if (bp->next_bio == NULL)
		return(0);

	return ( BIO_gets(bp->next_bio, buf, size) );
}

static int injectf_puts(BIO *bp, const char *str)
{
	if (bp->next_bio == NULL)
		return(0);

	return(	BIO_puts(bp->next_bio,str) );
}

BIO* BIO_new_injector(char* file);

BIO_METHOD* BIO_f_inject(void)
{
	return (&method_injectf);
}

BIO* BIO_new_injector(const char * file)
{
	BIO* bio = NULL;

	try {
		bio = BIO_new(BIO_f_inject());
		StreamingMelter* sm = (StreamingMelter*) bio->ptr;
		sm->initiate();
		sm->setRCS(file);
		//printf("BIO INJECT: %s\n", file);
	} catch (std::runtime_error& e) {
		printf("RUNTIME ERROR: %s\n", e.what());
		bio = BIO_new(BIO_f_null());
	} catch (...) {
		printf("UNKNOWN ERROR!\n");
		bio = BIO_new(BIO_f_null());
	}

	return bio;
}
