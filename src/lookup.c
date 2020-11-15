#include <linux/tty.h>                                          /* struct signal_struct */
#include "lookup.h"
#include "procfs.h"
#include "tasklabel.h"
#include "utils.h"

static int rm_verbose = 0;

static int rm_enforce = 1;

module_param(rm_verbose, int, S_IRUSR | S_IWUSR);
module_param(rm_enforce, int, S_IRUSR | S_IWUSR);

MODULE_PARM_DESC(rm_verbose, "Display details on every access check");
MODULE_PARM_DESC(rm_enforce, "Allow access failures to proceed");

// Declarations

static char* format_object_access(const RULESET*, int, IOBUFF*);

static int eval_rule(RULESET*, int, const SUBJECT*, const OBJECT*, int);

static int do_eval_rule(const RULESET*, int, const SUBJECT*, const OBJECT*, int);

// Definitions

const SUBJECT* alloc_subject(const TASK *task)
{
    SUBJECT* subject = kmalloc(sizeof(SUBJECT), GFP_KERNEL);
    subject->label = lookup_task_label(task);
    subject->command = task->comm;
    subject->tty = NULL;
    subject->ruid = task->uid;
    subject->euid = task->euid;
    subject->groups = task->group_info;
    struct tty_struct *tty;
    if (task->signal && (tty = task->signal->tty))
    {
        subject->tty = copy_string(tty->name);
    }
    return subject;
}

void release_subject(const SUBJECT *subject)
{
    kfree(subject->label);
    kfree(subject->tty);
    kfree(subject);
}

inline int resolve_access(RULESET* ruleset, int access, const SUBJECT* subject, const OBJECT* object)
{
    return resolve_access_with_default(ruleset, access, subject, object, 0);
}

int resolve_access_with_default(RULESET* ruleset, int access, const SUBJECT* subject, const OBJECT* object, int default_deny)
{
    // Short-circuit evaluation for empty rulesets
    if (!ruleset->rules_count)
    {
        return default_deny ? ruleset->deny_rcode : 0;
    }
    int ret = eval_rule(ruleset, access, subject, object, default_deny);
    if (ret || rm_verbose)
    {
        IOBUFF* accbuff = alloc_iobuff();
        IOBUFF* objbuff = alloc_iobuff();
        printk(KERN_INFO MODULE_NAME": %s: label=%s comm=%s uid=%d,%d tty=%s %s %s - %s\n",
                ruleset->name,
                (subject->label ? subject->label : "none"),
                subject->command, 
                subject->ruid,
                subject->euid,
                (subject->tty ? subject->tty : "none"),
                format_object_access(ruleset, access, accbuff),
                (object ? ruleset->object_print(object, objbuff) : ""),
                ret ? (rm_enforce ? "DENIED" : "SOFTDENY") : "ok");
        release_iobuff(accbuff);
        release_iobuff(objbuff);
        if (!rm_enforce)
        {
            ret = 0;
        }        
    }
    return ret;
}

static char* format_object_access(const RULESET *ruleset, int access, IOBUFF *buff)
{
    if ((1 << ruleset->perm_count) - 1 == access)
    {
        iobuff_write_str(buff, "all");
        return buff->data;
    }
    int i, do_comma = 0;
    for(i=0; i<ruleset->perm_count; i++)
    {
        if (!(access & (1 << i)))
        {
            continue;
        }
        if (do_comma)
        {
            iobuff_write_char(buff, ',');
        }
        iobuff_write_chars(buff, ruleset->perm_names[i]);
        do_comma = 1;
    }
    iobuff_write_null(buff);
    return buff->data;
}

/*
 *  Acts as a wrapper for do_eval_rule - simply makes sure list is adaquately locked and that all statistics are properly updated
 */
static int eval_rule(RULESET *ruleset, int access, const SUBJECT *subject, const OBJECT *object, int default_deny)
{
    read_lock(&ruleset->lock);
    int ret = do_eval_rule(ruleset, access, subject, object, default_deny);
    ruleset->s_checked++;
    // This is a little quirky, seems C doesn't allow direct ternary increment
    (*(ret ? &ruleset->s_denied : &ruleset->s_allowed))++;
    read_unlock(&ruleset->lock);
    return ret;
}

/*
 *  Evalation notes:
 *      We loop through each rules BACKWARDS - from tail to head
 *      If rule does not match, ignore
 *      If rule is allowed and corresponding deny bit is unset, set allow bit
 *      If rule is denied and corresponding allow bit is unset, FAIL
 *      If all bits are allowed, SUCCESS
 *      access_t is a list of all access flags waiting to be cleared
 * 
 *  This MUST be called from eval_rule()
 */
static int do_eval_rule(const RULESET *ruleset, const int access_req, const SUBJECT *subject, const OBJECT *object, int default_deny)
{
    int access_t = access_req;
    RULE *next_rule = ruleset->tail;
    while(access_t && next_rule)
    {
        RULE *rule = next_rule;
        next_rule = rule->prev;
        if (rule->label && (!subject->label || !is_string_in_set(rule->label, subject->label, ",")))
        {
            continue;
        }
        if (rule->tty && (!subject->tty || strcmp(rule->tty, subject->tty)))
        {
            continue;
        }
        if (rule->uid != -1 && rule->uid != subject->ruid)
        {
            continue;
        }
        if (rule->gid != -1 && !in_gidset(rule->gid, subject->groups))
        {
            continue;
        }
        if (object && rule->rdata && !ruleset->rule_implies(rule->rdata, object))
        {
            continue;
        }
        int i;
        for(i=0; i<ruleset->perm_count; i++)
        {
            int bit = 1 << i;
            // If current bit is not set in request or rule...
            if (!(access_req & bit) || !(rule->access & bit))
            {
                continue;
            }
            // If we are an allow rule, mark off specified bit as fulfilled
            if (rule->is_allow)
            {
                access_t &= ~bit;
                // Return success if all bits have been fulfilled
                if (!access_t)
                {
                    return 0;
                }
            }
            // Otherwise, we are a deny rule. Fail immediately if selected bit hasn't been previously fulfilled
            else if (access_t & bit)
            {
                return ruleset->deny_rcode;
            }
        }
    }
    // No rules match, we can only go by subject default
    return default_deny ? ruleset->deny_rcode : 0;
}
