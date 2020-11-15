#include <linux/uaccess.h>                                      /* copy_from_user */
#include <linux/proc_fs.h>                                      /* struct proc_dir_entry */
#include "procfs.h"

#define PROC_ENTRY struct proc_dir_entry
#define CONTAINER struct proc_container

struct proc_container
{
    char name[255];
    TAGDATA *tag;
    void (*user_read)(IOBUFF*, TAGDATA*);
    int (*user_write)(IOBUFF*, TAGDATA*);
};

// Declarations

static int generic_proc_read(char *page, char **start, off_t off, int count, int *eof, void *vdata);

static int generic_proc_write(struct file *file, const char __user *ubuff, unsigned long count, void *vdata);

// Members

static PROC_ENTRY *module_proc_root;

// Definitions

int procfs_init(void)
{
    module_proc_root = proc_mkdir(MODULE_NAME, NULL);
    if (!module_proc_root)
    {
        printk(KERN_ALERT MODULE_NAME": Couldn't initialise module proc root\n");
		return -EEXIST;
    }
    return 0;
}

void procfs_cleanup(void)
{
    if (module_proc_root)
    {
        remove_proc_entry(module_proc_root->name, NULL);
    }
    module_proc_root = NULL;
}

const PROCDATA* create_procfile(const char* name, int mode, TAGDATA *tag, void (*user_read)(IOBUFF*, TAGDATA*), int (*user_write)(IOBUFF*, TAGDATA*))
{
    PROC_ENTRY *entry = create_proc_entry(name, mode, module_proc_root);
    if (!entry)
    {
		return NULL;
    }
    CONTAINER *container = kmalloc(sizeof(CONTAINER), GFP_KERNEL);
    strncpy(container->name, name, sizeof(container->name));
    container->tag = tag;
    container->user_read = user_read;
    container->user_write = user_write;
    entry->data = container;
    if (container->user_read)
    {
        entry->read_proc = generic_proc_read;
    }
    if (container->user_write)
    {
        entry->write_proc = generic_proc_write;
    }
    return container;
}

void remove_procfile(const PROCDATA* pdata_v)
{
    remove_proc_entry(((CONTAINER*) pdata_v)->name, module_proc_root);
    kfree(pdata_v);
}

static int generic_proc_read(char *page, char **start, off_t off, int count, int *eof, void *vdata)
{
    if (off > 0)
    {
        return 0;
	}
    CONTAINER *container = vdata;
    IOBUFF* buff = alloc_iobuff();
    container->user_read(buff, container->tag);
    if (buff->pos > count)
    {
        release_iobuff(buff);
        return -ENOSPC;
    }
    memcpy(page, buff->data, buff->pos);
    int ret = buff->pos;
    release_iobuff(buff);
	return ret;
}

static int generic_proc_write(struct file *file, const char __user *ubuff, unsigned long count, void *vdata)
{
    if (count > PATH_MAX)
    {
        return -ENOSPC;
    }
    char* kbuff = kmalloc(count, GFP_KERNEL);
    if (copy_from_user(kbuff, ubuff, count))
    {
        kfree(kbuff);
        return -EFAULT;
    }
    IOBUFF* rbuff = alloc_iobuff();
    iobuff_write_data(rbuff, kbuff, count);
    // Make sure buffer is correctly null-terminated
    if (rbuff->data[rbuff->pos] != '\0')
    {
        iobuff_write_null(rbuff);
    }
    rbuff->pos = 0;
    kfree(kbuff);
    CONTAINER *container = vdata;
    int ret = container->user_write(rbuff, container->tag);
    release_iobuff(rbuff);
    if (ret < 0)
    {
        return ret;
    }
    return count;
}
