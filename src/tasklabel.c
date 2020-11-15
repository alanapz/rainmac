#include <linux/fs.h>                                           /* struct inode */
#include <linux/dcache.h>                                       /* struct dentry */
#include "tasklabel.h"
#include "utils.h"

#define XATTR_NAME "security.rainmac.label"

#define TASKENTRY_MAGIC 0x526D

#define IS_RM_TASK(t) ((t && t->security && ((TASKENTRY* )t->security)->magic == TASKENTRY_MAGIC))

typedef struct taskentry
{
    long magic;
    pid_t pid;
    char *label;
    TASK* task;
}   TASKENTRY;

// Declarations

static const TASKENTRY* set_task_label(TASK *task, const char* label);

// Members

extern SECURITY_OPERATIONS secondary_ops;

// Definitions

int tasklabel_init(void)
{
    // Not much to do here ...
    return 0;
}

void tasklabel_cleanup(void)
{
    // Not much to do here ...
}

int bprm_alloc_security_hook(LINUX_BINPRM *bprm)
{
    int result = secondary_ops.bprm_alloc_security(bprm);
    if (result)
    {
        return result;
    }
    if (!current->pid || current->pid == 1) 
    {
        return 0;
    }
    struct dentry* dentry;
    struct inode* inode;
    if (!bprm->file || !(dentry = bprm->file->f_dentry) || !(inode = dentry->d_inode))
    {
        // We either don't have a corresponding dentry, or we a negative dentry (file has been removed)
        return -EINVAL;
    }
    // If parent has been labelled then we automatically inherit security label from parent
    // TODO: Perhaps mark some labels as being non-inheritable ?
    if (IS_RM_TASK(current->parent))
    {
        set_task_label(current, ((TASKENTRY*) current->parent->security)->label);
        return 0;
    }
    // Otherwise, check to see whether our executable file has been labelled
    if (!inode->i_op->getxattr)
    {
        // FS does not support xattrs
        return 0;
    }
    char label[256];
    int label_t = inode->i_op->getxattr(dentry, XATTR_NAME, label, sizeof(label) - 1); // +1 for null
    if (label_t <= 0)
    {
        // File is not labelled or FS does not support labelling
        return 0;
    }
    label[label_t] = '\0';
    set_task_label(current, label);
    return 0;
}

static const TASKENTRY* set_task_label(TASK *task, const char* label)
{
    TASKENTRY *entry = kmalloc(sizeof(TASKENTRY), GFP_KERNEL);
    entry->magic = TASKENTRY_MAGIC;
    entry->pid = task->pid;
    entry->label = copy_string(label);
    entry->task = task;
    task->security = entry;
    return entry;
}

int task_alloc_security_hook(TASK *p)
{
    int result = secondary_ops.task_alloc_security(p);
    if (result)
    {
        return result;
    }
    if (!p->security && IS_RM_TASK(current))
    {
        set_task_label(p, ((TASKENTRY*) current->security)->label);
    }
    return 0;
}

void task_free_security_hook(TASK *p)
{
    secondary_ops.task_free_security(p);
    if (IS_RM_TASK(p))
    {
        TASKENTRY *entry = p->security;
        p->security = NULL;
        kfree(entry->label);
        kfree(entry);
    }
}

int getprocattr_hook(TASK *p, char *name, void *value, size_t size)
{
    if (!IS_RM_TASK(p))
    {
        return -EINVAL;
    }
    TASKENTRY *entry = p->security;
    int label_t = strlen(entry->label) + 1;
    if (size < label_t)
    {
        return -ENOSPC;
    }
    int ret = -EINVAL;
    if (!strcmp(name, "current"))
    {
        strcpy(value, entry->label);
        ret = label_t;
    }
    return ret;
}

int setprocattr_hook(TASK *p, char *name, void *value, size_t size)
{
    // We do not support relabelling tasks
    if (p->security)
    {
        return -EPERM;
    }
    if (!size || strcmp(name, "current"))
    {
        return -EINVAL;
    }
    char* buff = normalise_string(value, size);
    set_task_label(p, buff);
    kfree(buff);
    return size;
}

inline const char* lookup_task_label(const TASK *task)
{
    return IS_RM_TASK(task) ? copy_string(((TASKENTRY *) task->security)->label) : NULL;
}
