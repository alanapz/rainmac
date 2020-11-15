#ifndef LOOKUP_H
#define	LOOKUP_H

#include <linux/types.h>                                        /* gid_t */
#include "shared.h"
#include "ruleset.h"

#define SUBJECT struct subject

struct subject
{
    const char *label;
    const char *command;
    const char *tty;
    uid_t ruid;
    uid_t euid;
    const GROUP_INFO *groups;
};

const SUBJECT* alloc_subject(const TASK*);

void release_subject(const SUBJECT*);

int resolve_access(RULESET*, int access, const SUBJECT*, const OBJECT*);

int resolve_access_with_default(RULESET*, int access, const SUBJECT*, const OBJECT*, int);

#endif
