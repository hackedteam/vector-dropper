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
#define BIO_CTRL_SET_DEBUG_FN  (99)

#ifdef __cplusplus
extern "C" {
#endif
BIO* BIO_new_injector(const char * file);
#ifdef __cplusplus
}
#endif

#endif /* MELT_H_ */
