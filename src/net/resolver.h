/*
** resolver.h
**
** name resolver library header
**
*/

#ifndef __RESOLVER_H
#define __RESOLVER_H


/*
** resolver_lookup
**
** resolves a hosts name from it's ip address
** or
** resolves an ip address from it's host name
**
** returns a pointer to buff, or NULL if an error occured
**
*/

#ifdef _mangle
# define resolver_initialize _mangle(resolver_initialize)
# define resolver_shutdown _mangle(resolver_shutdown)
# define resolver_getname _mangle(resolver_getname)
# define resolver_getip _mangle(resolver_getip)
#endif

void resolver_initialize(void);
void resolver_shutdown(void);

char *resolver_getname(const char *ip : itype(_Nt_array_ptr<const char>) count(len), char *buff : itype(_Array_ptr<char>) count(len), int len) : itype(_Ptr<char>);
char *resolver_getip(const char *name : itype(_Nt_array_ptr<const char>) count(46), char *buff : itype(_Array_ptr<char>) count(len), int len) : itype(_Ptr<char>);

#endif





