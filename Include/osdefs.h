#ifndef Py_OSDEFS_H
#define Py_OSDEFS_H
#ifdef __cplusplus
extern "C" {
#endif


/* Operating system dependencies */

#ifdef MS_WINDOWS
#define SEP L'\\'
#define ALTSEP L'/'
#define MAXPATHLEN 256
#define DELIM L';'
#ifdef TARGET_WINDOWS_STORE
#include <minwindef.h>
typedef struct _BY_HANDLE_FILE_INFORMATION {
	DWORD dwFileAttributes;
	FILETIME ftCreationTime;
	FILETIME ftLastAccessTime;
	FILETIME ftLastWriteTime;
	DWORD dwVolumeSerialNumber;
	DWORD nFileSizeHigh;
	DWORD nFileSizeLow;
	DWORD nNumberOfLinks;
	DWORD nFileIndexHigh;
	DWORD nFileIndexLow;
} BY_HANDLE_FILE_INFORMATION, *PBY_HANDLE_FILE_INFORMATION, *LPBY_HANDLE_FILE_INFORMATION;
#endif
#endif

/* Filename separator */
#ifndef SEP
#define SEP L'/'
#endif

/* Max pathname length */
#ifdef __hpux
#include <sys/param.h>
#include <limits.h>
#ifndef PATH_MAX
#define PATH_MAX MAXPATHLEN
#endif
#endif

#ifndef MAXPATHLEN
#if defined(PATH_MAX) && PATH_MAX > 1024
#define MAXPATHLEN PATH_MAX
#else
#define MAXPATHLEN 1024
#endif
#endif

/* Search path entry delimiter */
#ifndef DELIM
#define DELIM L':'
#endif

#ifdef __cplusplus
}
#endif
#endif /* !Py_OSDEFS_H */
