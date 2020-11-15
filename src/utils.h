#ifndef UTILS_H
#define	UTILS_H

#include <linux/types.h>        /* gid_t */
#include <linux/sched.h>        /* struct group_info */

char* copy_string(const char *in);

/*
 * Appends trailing null to a string and removes any trailing whitespace
 * Caller must kfree returned string
 */
char* normalise_string(const char *in, int size);

int is_string_in_set(const char *needle, const char *haystack, const char* delim);

int hash_string(const char *data);

int in_gidset(gid_t gid, const struct group_info *groups);

#include "iobuff.h"

#endif
