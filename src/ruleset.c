#include <linux/module.h>                                       /* kmalloc etc */
#include <linux/stat.h>                                         /* S_rxw etc */
#include "ruleset.h"
#include "utils.h"

#define CONTAINER struct ruleset_container

struct ruleset_container
{
    RULESET *ruleset;
    CONTAINER *next;
    CONTAINER *prev;
};

static rwlock_t container_lock;

static CONTAINER *container_head, *container_tail;

const static PROCDATA* proc_statsfile;

static void print_ruleset_stats(IOBUFF*, TAGDATA*);
static void delete_rule(RULE*);
static void export_ruleset(IOBUFF*, TAGDATA*);
static void export_rule(int*, const RULE*, IOBUFF*);
static int ruleset_proc_input(IOBUFF*, TAGDATA*);
static void flush_ruleset(RULESET*);
static char* iobuff_read_token(IOBUFF*);

#include "ruleset-util.c"

int ruleset_init(void)
{
    rwlock_init(&container_lock);
    proc_statsfile = create_procfile("stats", S_IRUSR, NULL, print_ruleset_stats, NULL);
    if (!proc_statsfile)
    {
        printk(KERN_ALERT MODULE_NAME": Couldn't initialise ruleset stats\n");
		return -EEXIST;
    }
    return 0;
}

void ruleset_cleanup(void)
{
    if (proc_statsfile)
    {
        remove_procfile(proc_statsfile);
    }
}

static void print_ruleset_stats(IOBUFF *buff, TAGDATA *tag_v)
{
    iobuff_csprintf(buff, "%-12s\t%-6s %-6s %-6s %-6s %-6s %-6s\n",
        "",
        "rules",
        "count",
        "ok",
        "fail",
        "ch",
        "cm");
    read_lock(&container_lock);
    {
        CONTAINER *container = container_head;
        while(container)
        {
            RULESET* ruleset = container->ruleset;
            iobuff_csprintf(buff, "%-12s\t%-6d %-6u %-6u %-6u %-6u %-6u\n",
                    ruleset->name,
                    ruleset->rules_count,
                    ruleset->s_checked,
                    ruleset->s_allowed,
                    ruleset->s_denied,
                    0,
                    0);
            container = container->next;
        }
    }
    read_unlock(&container_lock);
    iobuff_write_null(buff);
}

RULESET* alloc_ruleset(const char *name, const char **perm_names, int perm_count)
{
    RULESET* ruleset = kmalloc(sizeof(RULESET), GFP_KERNEL);
    ruleset->name = name;
    rwlock_init(&ruleset->lock);
    ruleset->head = NULL;
    ruleset->tail = NULL;
    ruleset->rules_count = 0;
    ruleset->perm_names = perm_names;
    ruleset->perm_count = perm_count;
    ruleset->deny_rcode = -EACCES;
    ruleset->s_checked = ruleset->s_allowed = ruleset->s_denied = 0;
    ruleset->rule_implies = NULL;
    ruleset->object_print = NULL;
    ruleset->rdata_export = NULL;
    ruleset->rdata_destroy = NULL;
    ruleset->procfile = create_procfile(name, S_IRUSR | S_IWUSR, ruleset, export_ruleset, ruleset_proc_input);
    if (!ruleset->procfile)
    {
        kfree(ruleset);
        return NULL;
    }
    CONTAINER *container = kmalloc(sizeof(CONTAINER), GFP_KERNEL);
    container->ruleset = ruleset;
    ruleset->container = container;
    container->next = container->prev = NULL;
    write_lock(&container_lock);
    {
        if (!container_head)
        {
            container_head = container;
        }
        CONTAINER *prev = container_tail;
        if (prev)
        {
            prev->next = container;
            container->prev = prev;
        }
        container_tail = container;
    }
    write_unlock(&container_lock);
    return ruleset;
}

void release_ruleset(RULESET *ruleset)
{
    remove_procfile(ruleset->procfile);
    // Yes, this is a gigantic memory leak - we do not clean up rulesets or rules properly
    // (At least we don't have to lock on ruleset here)
    while(ruleset->rules_count)
    {
        delete_rule(ruleset->head);
    }
    kfree(ruleset);
}

RULE* add_rule(RULESET *ruleset, bool is_allow, int access, const RDATA *rdata)
{
    RULE* rule = kmalloc(sizeof(RULE), GFP_KERNEL);
    rule->is_allow = is_allow;
    rule->access = access;
    rule->label = NULL;
    rule->tty = NULL;
    rule->uid = -1;
    rule->gid = -1;
    rule->rdata = rdata;
    rule->ruleset = ruleset;
    rule->next = rule->prev = NULL;
    write_lock(&ruleset->lock);
    {
        ruleset->rules_count++;
        if (!ruleset->head)
        {
            ruleset->head = rule;
        }
        RULE *prev = ruleset->tail;
        if (prev)
        {
            prev->next = rule;
            rule->prev = prev;
        }
        ruleset->tail = rule;
    }
    write_unlock(&ruleset->lock);
    return rule;
}

static void delete_rule(RULE *rule)
{
    if (rule->rdata)
    {
        rule->ruleset->rdata_destroy(rule->rdata);
    }
    // If we have a predecessor, set predecessor's successor to our successor
    if (rule->prev)
    {
        rule->prev->next = rule->next;
    }
    // If we have a successor, set successor's predecessor to our predecessor
    if (rule->next)
    {
        rule->next->prev = rule->prev;
    }
    // If we are list head (first), set list head to our successor
    if (rule == rule->ruleset->head)
    {
        rule->ruleset->head = rule->next;
    }
    // If we are list tail (last), set list tail to our predecessor
    if (rule == rule->ruleset->tail)
    {
        rule->ruleset->tail = rule->prev;
    }
    kfree(rule->label);
    kfree(rule->tty);
    rule->ruleset->rules_count--;
}

static void export_ruleset(IOBUFF *buff, TAGDATA *tag_v)
{
    RULESET *ruleset = tag_v;
    int index = 0;
    read_lock(&ruleset->lock);
    {
        RULE* rule = ruleset->head;
        while(rule)
        {
            export_rule(&index, rule, buff);
            rule = rule->next;
        }
    }
    read_unlock(&ruleset->lock);
    iobuff_write_null(buff);
}

static void export_rule(int *index, const RULE *rule, IOBUFF *buff)
{
    iobuff_csprintf(buff, "%d\t%s ", ++(*index), rule->is_allow ? "permit" : "prohibit");
    if ((1 << rule->ruleset->perm_count) - 1 == rule->access)
    {
        iobuff_write_chars(buff, "all");
    }
    else
    {
        int i, do_comma = 0;
        for(i=0; i<rule->ruleset->perm_count; i++)
        {
            if (!(rule->access & (1 << i)))
            {
                continue;
            }
            if (do_comma)
            {
                iobuff_write_char(buff, ',');
            }
            iobuff_write_chars(buff, rule->ruleset->perm_names[i]);
            do_comma = 1;
        }
    }
    if (rule->label)
    {
        iobuff_csprintf(buff, " by label %s", rule->label);
    }
    if (rule->tty)
    {
        iobuff_csprintf(buff, " by terminal %s", rule->tty);
    }
    if (rule->uid != -1)
    {
        iobuff_csprintf(buff, " by user %d", rule->uid);
    }
    if (rule->gid != -1)
    {
        iobuff_csprintf(buff, " by group %d", rule->gid);
    }
    if (rule->rdata)
    {
        iobuff_write_chars(buff, " to ");
        rule->ruleset->rdata_export(rule->rdata, buff);
    }
    iobuff_write_char(buff, '\n');
}

static int ruleset_proc_input(IOBUFF *buff, TAGDATA *tag_v)
{
    RULESET *ruleset = tag_v;
    char *action = iobuff_read_token(buff);
    if (!action)
    {
        return -EINVAL;
    }
    int ok = 0;
    if (!strcmp(action, "clear"))
    {
        flush_ruleset(ruleset);
        ok = 1;
    }
    else if (!strcmp(action, "delete"))
    {
        ok = command_delete(ruleset, buff);
    }
    else if (!strcmp(action, "permit"))
    {
        ok = command_insert(ruleset, buff, 1);
    }
    else if (!strcmp(action, "prohibit"))
    {
        ok = command_insert(ruleset, buff, 0);
    }
    kfree(action);
    return ok ? 0 : -EINVAL;
}

static void flush_ruleset(RULESET *ruleset)
{
    write_lock(&ruleset->lock);
    {
        ruleset->s_checked = ruleset->s_allowed = ruleset->s_denied = 0;
        while(ruleset->rules_count > 0)
        {
            delete_rule(ruleset->head);
        }
    }
    write_unlock(&ruleset->lock);
}

/*
 *  This is a little hairy and could be improved - perhaps fencepost error?
 */
static char* iobuff_read_token(IOBUFF *buff)
{
    // Advance past any whitespace (\t, \n, ' ')
    // (This presumes we are correctly null-terminated)
    for(;;)
    {
        char c = buff->data[buff->pos];
        if (!c)
        {
            return NULL;
        }
        if (c != '\t' && c != '\n' && c != ' ')
        {
            break;
        }
        buff->pos++;
    }
    int start = buff->pos;
    for(;;)
    {
        char c = buff->data[buff->pos];
        if (c == '\0' || c == '\t' || c == '\n' || c == ' ')
        {
            break;
        }
        buff->pos++;
    }
    char *ret = kmalloc(buff->pos - start + 1, GFP_KERNEL); // Remember +1 for trailing null
    memcpy(ret, &buff->data[start], buff->pos - start);
    ret[buff->pos - start] = '\0';
    return ret;
}
