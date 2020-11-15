#ifndef RULESET_H
#define	RULESET_H

#include <linux/types.h>                                        /* uid_t, gid_t */
#include <linux/spinlock.h>
#include "procfs.h"                                             /* PROCDATA */
#include "shared.h"
#include "utils.h"

#define RULE struct rule
#define RULESET struct ruleset

typedef void RDATA;
typedef void OBJECT;

struct rule
{
    bool is_allow;
    int access;
    const char *label;
    const char *tty;
    uid_t uid;
    gid_t gid;
    const RDATA *rdata;
    RULESET *ruleset;
    RULE *next;
    RULE *prev;
    /* Statistics */
    unsigned s_matches;
};

struct ruleset
{
    const char *name;
    rwlock_t lock;
    RULE *head;
    RULE *tail;
    int rules_count;
    const char **perm_names;
    int perm_count;
    int deny_rcode;     // Typically either -EACCES or -EPERM
    /* Statistics */
    unsigned s_checked;
    unsigned s_allowed;
    unsigned s_denied;
    /* Operations */
    int (*rule_implies)(const RDATA*, const OBJECT*);
    const char* (*object_print)(const OBJECT*, IOBUFF*);
    RDATA* (*rdata_import)(const char*);
    void (*rdata_export)(const RDATA*, IOBUFF*);
    void (*rdata_destroy)(const RDATA*);
    /* Private data for use by other modules */
    const void *container;
    const PROCDATA *procfile;
};

int ruleset_init(void);

void ruleset_cleanup(void);

RULESET* alloc_ruleset(const char *name, const char **perm_names, int perm_count);

void release_ruleset(RULESET*);

RULE* add_rule(RULESET*, bool is_allow, int access, const RDATA*);

#endif
