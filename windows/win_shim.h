/*
 * win_shim.h — Windows/mingw compatibility shim for hcxtools.
 *
 * Force-included on the Windows build only (via CPPFLAGS="-include windows/win_shim.h").
 * It supplies POSIX/BSD helpers that the mingw-w64 C runtime does not provide,
 * so the upstream hcxtools sources compile UNMODIFIED.
 *
 * hcxtools is (C) ZeroBeat, MIT licensed — https://github.com/ZerBea/hcxtools
 */
#ifndef HCX_WIN_SHIM_H
#define HCX_WIN_SHIM_H
#ifdef _WIN32
#include <string.h>

/*
 * BSD strsep(): split *stringp on any byte in delim. Returns the token before
 * the first delimiter (NUL-terminating it) and advances *stringp past it;
 * returns the whole remaining string (and sets *stringp = NULL) when no
 * delimiter is present; returns NULL when *stringp is already NULL.
 */
static char *strsep(char **stringp, const char *delim)
{
	char *start = *stringp;
	char *p;
	if (start == NULL)
		return NULL;
	p = start + strcspn(start, delim);
	if (*p != '\0')
	{
		*p = '\0';
		*stringp = p + 1;
	}
	else
		*stringp = NULL;
	return start;
}
#endif /* _WIN32 */
#endif /* HCX_WIN_SHIM_H */
