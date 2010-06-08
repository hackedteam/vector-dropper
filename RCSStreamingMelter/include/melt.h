/*
 * melt.h
 *
 *  Created on: Apr 26, 2010
 *      Author: daniele
 */

#ifndef MELT_H_
#define MELT_H_

#include <openssl/bio.h>

#define BIO_TYPE_INJECT_FILTER (99|0x200)

#ifdef __cplusplus
extern "C" {
#endif
BIO* BIO_new_injector(const char * file);
//int BIO_set_backdoor(BIO* bio, const char* file);
//BIO_METHOD* BIO_f_inject(void);
//int BIO_get_size(BIO* bio, int size);
#ifdef __cplusplus
}
#endif

#endif /* MELT_H_ */
