PHP_ARG_ENABLE(melt, whether to enable pe melting support, 
	[ --enable-melt Enable PE melting support])
	
if test "$PHP_MELT" = "yes"; then
	AC_DEFINE(HAVE_MELT, 1, [Whether you have PE melting])
	PHP_NEW_EXTENSION(php_melter, php_melter.c, $ext_shared)
fi