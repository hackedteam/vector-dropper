/*
 * php_melter.c
 *
 *  Created on: May 7, 2010
 *      Author: daniele
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <php.h>
#include "php_melter.h"

static function_entry melter_functions[] = {
		PHP_FE(pe_melt, NULL)
		{NULL, NULL, NULL}
};

zend_module_entry melter_module_entry = {
#if ZEND_MODULE_API_NO >= 20010901
		STANDARD_MODULE_HEADER,
#endif
		PHP_MELTER_EXTNAME,
		melter_functions,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
#if ZEND_MODULE_API_NO >= 20010901
		PHP_MELTER_VERSION,
#endif
		STANDARD_MODULE_PROPERTIES
};

#ifdef COMPILE_DL_MELTER
ZEND_MODULE_GET(melter)
#endif

PHP_FUNCTION(pe_melt)
{
	 char *str;

	str = estrdup("PE melting not implemented.");
	RETURN_STRING(str, 0);
}

