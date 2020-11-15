#include <linux/stat.h>                                         /* S_ISUID etc */
#include "fsmac.h"
#include "ruleset.h"
#include "lookup.h"
#include "utils.h"

#define PERM_FS_READ        1
#define PERM_FS_WRITE       2
#define PERM_FS_EXECUTE     4
#define PERM_FS_RUNAS       8                                   /* Allows exec of SUID/SGID programs */
#define PERM_FS_LINK        16

#define FS_OBJECT           struct fs_object

struct fs_object
{
    char *path;
};

// Declarations

static FS_OBJECT* alloc_fs_object(void);

static void release_fs_object(const FS_OBJECT*);

static char* lookup_inode_path(const INODE*, char[PATH_MAX]);

static char* lookup_dentry_path(const DENTRY*, char[PATH_MAX]);

static void build_dentry_path(const DENTRY*, const DENTRY*[PATH_MAX], char[PATH_MAX]);

// File-system object rule operators

static int r_fs_rule_implies(const RDATA*, const OBJECT*);

static const char* r_fs_object_print(const OBJECT*, IOBUFF*);

static RDATA* r_fs_rdata_import(const char*);

static void r_fs_rdata_export(const RDATA*, IOBUFF*);

static void r_fs_rdata_destroy(const RDATA*);

// Members

static RULESET *fs_ruleset;

static const char *fs_perm_names[] = { "read" , "write", "execute", "runas", "link" };

extern SECURITY_OPERATIONS secondary_ops;

// Definitions

int fsmac_init(void)
{
    fs_ruleset = alloc_ruleset("fs", fs_perm_names, 5);
    if (!fs_ruleset)
    {
        return -EIO;
    }
    fs_ruleset->rule_implies = r_fs_rule_implies;
    fs_ruleset->object_print = r_fs_object_print;
    fs_ruleset->rdata_import = r_fs_rdata_import;
    fs_ruleset->rdata_export = r_fs_rdata_export;
    fs_ruleset->rdata_destroy = r_fs_rdata_destroy;
    return 0;
}

void fsmac_cleanup(void)
{
    if (fs_ruleset)
    {
        release_ruleset(fs_ruleset);
    }
}

int inode_create_hook(INODE *inode, DENTRY *dentry, int mask)
{
    int result = secondary_ops.inode_create(inode, dentry, mask);
    if (result)
    {
        return result;
    }
    if (!current->pid || current->pid == 1) 
    {
        return 0;
    }
    const SUBJECT* subject = alloc_subject(current);
    FS_OBJECT* object = alloc_fs_object();
    lookup_dentry_path(dentry, object->path);
    result = resolve_access(fs_ruleset, PERM_FS_WRITE, subject, object);
    release_fs_object(object);
    release_subject(subject);
    return result;
}
 
int inode_link_hook(DENTRY *src_dentry, INODE *inode, DENTRY *target_dentry)
{
    int result = secondary_ops.inode_link(src_dentry, inode, target_dentry);
    if (result)
    {
        return result;
    }
    if (!current->pid || current->pid == 1) 
    {
        return 0;
    }
    const SUBJECT* subject = alloc_subject(current);
    FS_OBJECT* object = alloc_fs_object();
    lookup_dentry_path(target_dentry, object->path);
    result = resolve_access(fs_ruleset, PERM_FS_LINK | PERM_FS_WRITE, subject, object);
    release_fs_object(object);
    release_subject(subject);
    return result;
}

int inode_unlink_hook(INODE *inode, DENTRY *dentry)
{
    int result = secondary_ops.inode_unlink(inode, dentry);
    if (result)
    {
        return result;
    }
    if (!current->pid || current->pid == 1) 
    {
        return 0;
    }
    const SUBJECT* subject = alloc_subject(current);
    FS_OBJECT* object = alloc_fs_object();
    lookup_dentry_path(dentry, object->path);
    result = resolve_access(fs_ruleset, PERM_FS_WRITE, subject, object);
    release_fs_object(object);
    release_subject(subject);
    return result;
}

int inode_symlink_hook(INODE *inode, DENTRY *dentry, const char *name)
{
    int result = secondary_ops.inode_symlink(inode, dentry, name);
    if (result)
    {
        return result;
    }
    if (!current->pid || current->pid == 1) 
    {
        return 0;
    }
    const SUBJECT* subject = alloc_subject(current);
    FS_OBJECT* object = alloc_fs_object();
    lookup_dentry_path(dentry, object->path);
    result = resolve_access(fs_ruleset, PERM_FS_LINK | PERM_FS_WRITE, subject, object);
    release_fs_object(object);
    release_subject(subject);
    return result;
}

int inode_mkdir_hook(INODE *inode, DENTRY *dentry, int mask)
{
    int result = secondary_ops.inode_mkdir(inode, dentry, mask);
    if (result)
    {
        return result;
    }
    if (!current->pid || current->pid == 1) 
    {
        return 0;
    }
    const SUBJECT* subject = alloc_subject(current);
    FS_OBJECT* object = alloc_fs_object();
    lookup_dentry_path(dentry, object->path);
    result = resolve_access(fs_ruleset, PERM_FS_WRITE, subject, object);
    release_fs_object(object);
    release_subject(subject);
    return result;
}

int inode_rmdir_hook(INODE *inode, DENTRY *dentry)
{
    int result = secondary_ops.inode_rmdir(inode, dentry);
    if (result)
    {
        return result;
    }
    if (!current->pid || current->pid == 1) 
    {
        return 0;
    }
    const SUBJECT* subject = alloc_subject(current);
    FS_OBJECT* object = alloc_fs_object();
    lookup_dentry_path(dentry, object->path);
    result = resolve_access(fs_ruleset, PERM_FS_WRITE, subject, object);
    release_fs_object(object);
    release_subject(subject);
    return result;
}

int inode_setattr_hook(DENTRY *dentry, IATTR *iattr)
{
    int result = secondary_ops.inode_setattr(dentry, iattr);
    if (result)
    {
        return result;
    }
    if (!current->pid || current->pid == 1) 
    {
        return 0;
    }
    if (!(iattr->ia_valid & ATTR_MODE) && !(iattr->ia_valid & ATTR_UID) && !(iattr->ia_valid & ATTR_GID))
    {
        return 0;
    }
    const SUBJECT* subject = alloc_subject(current);
    FS_OBJECT* object = alloc_fs_object();
    lookup_dentry_path(dentry, object->path);
    result = resolve_access(fs_ruleset, PERM_FS_WRITE, subject, object);
    release_fs_object(object);
    release_subject(subject);
    return result;
}

int inode_access_hook(INODE *inode, int mask, NAMEIDATA *nd)
{
    int result = secondary_ops.inode_permission(inode, mask, nd);
    if (result)
    {
        return result;
    }
    // Also skip check if we are not a regular file, or if we are performing a null (existence) check
    if (!current->pid || current->pid == 1 || !S_ISREG(inode->i_mode) || !mask)
    {
        return 0;
    }    
    int access = 0;
    if (mask & MAY_READ)
    {
        access |= PERM_FS_READ;
    }
    if (mask & MAY_WRITE || mask & MAY_APPEND)
    {
        access |= PERM_FS_WRITE;
    }
    if (mask & MAY_EXEC)
    {
        access |= PERM_FS_EXECUTE;
        if (inode->i_mode & S_ISUID || inode->i_mode & S_ISGID)
        {
            access |= PERM_FS_RUNAS;
        }
    }
    if (!access)
    {
        return 0;
    }
    const SUBJECT* subject = alloc_subject(current);
    FS_OBJECT* object = alloc_fs_object();
    // We have to lookup path by inode here - very messy !
    lookup_inode_path(inode, object->path);
    result = resolve_access(fs_ruleset, access, subject, object);
    release_fs_object(object);
    release_subject(subject);
    return result;
}


static FS_OBJECT* alloc_fs_object(void)
{
    FS_OBJECT *object = kmalloc(sizeof(FS_OBJECT), GFP_KERNEL);
    object->path = kzalloc(PATH_MAX, GFP_KERNEL);
    return object;
}

static void release_fs_object(const FS_OBJECT* object)
{
    kfree(object->path);
    kfree(object);
}

static char* lookup_inode_path(const INODE *inode, char path_buff[PATH_MAX])
{
    struct list_head *d_iter;
    const DENTRY **dentry_buff = kmalloc(sizeof(DENTRY*) * PATH_MAX, GFP_KERNEL);
    spin_lock(&dcache_lock);
    list_for_each(d_iter, &inode->i_dentry)
    {
        // TODO: Inodes can have multiple dentries - here we only use the first one
        DENTRY *dentry = list_entry(d_iter, DENTRY, d_alias);
        build_dentry_path(dentry, dentry_buff, path_buff);
        break;
    }
    spin_unlock(&dcache_lock);
    kfree(dentry_buff);
    return path_buff;
}

static char* lookup_dentry_path(const DENTRY *dentry, char path_buff[PATH_MAX])
{
    const DENTRY **dentry_buff = kmalloc(sizeof(DENTRY*) * PATH_MAX, GFP_KERNEL);
    spin_lock(&dcache_lock);
    build_dentry_path(dentry, dentry_buff, path_buff);
    spin_unlock(&dcache_lock);
    kfree(dentry_buff);
    return path_buff;
}

static void build_dentry_path(const DENTRY *dentry, const DENTRY *dentry_buff[PATH_MAX], char path_buff[PATH_MAX])
{
    int dentry_p = -1;
    while(dentry && dentry != dentry->d_parent)
    {
        dentry_buff[++dentry_p] = dentry;
        dentry = dentry->d_parent;
    }
    int path_p = -1;     
    int i;
    for(i = dentry_p; i >= 0; i--)
    {
        struct qstr d_name = dentry_buff[i]->d_name;
        path_buff[++path_p] = '/';
        memcpy(&path_buff[++path_p], d_name.name, d_name.len);
        path_p += d_name.len - 1;
    }
    path_buff[++path_p] = '\0';
}

static int r_fs_rule_implies(const RDATA *rdata_v, const OBJECT *object_v)
{
    const FS_OBJECT *rdata = rdata_v;
    const FS_OBJECT *object = object_v;
    if (rdata->path && object->path)
    {
        const char *rpath = rdata->path;
        const char *opath = object->path;
        // The next line has been the source of many bugs
        if ((rpath[strlen(rpath) - 1] != '/' && strcmp(rpath, opath))
                || (rpath[strlen(rpath) - 1] == '/' && strncmp(rpath, opath, strlen(rpath) - 1)))
        {
            return 0;
        }
    }
    return 1;
}

static const char* r_fs_object_print(const OBJECT *object_v, IOBUFF *buff)
{
    return ((const FS_OBJECT*) object_v)->path;
}

static RDATA* r_fs_rdata_import(const char *rdata)
{
    FS_OBJECT *object = kmalloc(sizeof(FS_OBJECT), GFP_KERNEL);
    object->path = copy_string(rdata);
    return object; 
}

static void r_fs_rdata_export(const RDATA *rdata_v, IOBUFF *buff)
{
    iobuff_write_chars(buff, ((const FS_OBJECT*) rdata_v)->path);
}

static void r_fs_rdata_destroy(const RDATA *rdata_v)
{
    kfree(((FS_OBJECT*) rdata_v)->path);
    kfree(rdata_v);
}
