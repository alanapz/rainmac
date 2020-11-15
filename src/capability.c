#include "capability.h"
#include "ruleset.h"
#include "lookup.h"

#define PERM_CAP_NET_BIND   1
#define PERM_CAP_NET_RAW    2
#define PERM_CAP_REBOOT     4
#define PERM_CAP_SETTIME    8
#define PERM_CAP_KERNEL     16
#define PERM_CAP_PTRACE     32

// Members

static RULESET *capability_ruleset;

static const char *capability_perm_names[] = { "bindanyport", "rawsocket", "reboot", "setclock", "kernelmodule", "ptrace" };

extern SECURITY_OPERATIONS secondary_ops;

static int cap_perm_ids[255];

// Definitions

int capability_init(void)
{
    capability_ruleset = alloc_ruleset("privileges", capability_perm_names, 6);
    if (!capability_ruleset)
    {
        return -EIO;
    }
    capability_ruleset->deny_rcode = -EPERM;
    cap_perm_ids[CAP_NET_BIND_SERVICE] = PERM_CAP_NET_BIND;
    cap_perm_ids[CAP_NET_RAW] = PERM_CAP_NET_RAW;
    cap_perm_ids[CAP_SYS_BOOT] = PERM_CAP_REBOOT;
    cap_perm_ids[CAP_SYS_TIME] = PERM_CAP_SETTIME;
    cap_perm_ids[CAP_SYS_MODULE] = PERM_CAP_KERNEL;
    return 0;
}

void capability_cleanup(void)
{
    if (capability_ruleset)
    {
        release_ruleset(capability_ruleset);
    }
}

int capable_hook(TASK *task, const int cap)
{
    int result = secondary_ops.capable(task, cap);
    // Return parent access result if we are not willing to handle this request
    if (!current->pid || current->pid == 1)
    {
        return result;
    }
    if (cap < 0 || cap > 255 || !cap_perm_ids[cap])
    {
        return result;
    }
    const SUBJECT* subject = alloc_subject(task);
    result = resolve_access_with_default(capability_ruleset, cap_perm_ids[cap], subject, NULL, result);
    release_subject(subject);
    return result;
}

int ptrace_hook(TASK *parent, TASK *child)
{
    int result = secondary_ops.ptrace(parent, child);
    if (result)
    {
        return result;
    }
    if (!current->pid || current->pid == 1)
    {
        return 0;
    }
    const SUBJECT* subject = alloc_subject(parent);
    result = resolve_access(capability_ruleset, PERM_CAP_PTRACE, subject, NULL);
    release_subject(subject);
    return result;
}
