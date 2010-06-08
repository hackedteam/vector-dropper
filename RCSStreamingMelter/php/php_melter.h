/*
 * php_melter.h
 *
 *  Created on: May 7, 2010
 *      Author: daniele
 */

#ifndef PHP_MELTER_H_
#define PHP_MELTER_H_

#define PHP_MELTER_VERSION "1.0"
#define PHP_MELTER_EXTNAME "melter"

PHP_FUNCTION(pe_melt);

extern zend_module_entry melter_module_entry;
#define phpext_melter_ptr &melter_module_entry;

#endif /* PHP_MELTER_H_ */
