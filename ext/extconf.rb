require "mkmf"

have_header "pthread.h"

pkg_config "openssl"
have_header "openssl/sha.h"
have_func "SHA1"

create_makefile "gitsha"
