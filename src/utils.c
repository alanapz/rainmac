#include "utils.h"
#include <linux/string.h>

// Definitions

char* copy_string(const char *in)
{
    if (!in)
    {
        return NULL;
    }
    char *out = kmalloc(strlen(in) + 1, GFP_KERNEL);
    strcpy(out, in);
    return out;
}

char* normalise_string(const char *in, int size)
{
    char *buff = kmalloc(size+1, GFP_KERNEL);
    memcpy(buff, in, size);
    // Replace trailing whitespace if necessary
    char *last = &buff[size-1];
    if (*last == '\n' || *last == ' ' || *last == '\t')
    {
        *last = '\0';
    }
    // Append trailing null
    buff[size] = '\0';
    return buff;
}

int is_string_in_set(const char *needle, const char *haystack, const char* delim)
{
    int found  = 0;
    char *buff = copy_string(haystack);
    char *token;
    while((token = strsep(&buff, delim)))
    {
        if (!strcmp(needle, token))
        {
            found = 1;
            break;
        }
    }
    kfree(buff);
    return found;
}

int hash_string(const char *data)
{
    // TODO: Implement a better hash function !
    return strlen(data);
}

int in_gidset(gid_t gid, const struct group_info *groups)
{
    int i;
    for(i=0; i<groups->ngroups; i++)
    {
        if (gid == GROUP_AT(groups, i))
        {
            return -1;
        }
    }
    return 0;
}

#include "iobuff.c"
