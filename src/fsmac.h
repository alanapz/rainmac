#ifndef FSMAC_H
#define	FSMAC_H

#include <linux/fs.h>                                           /* struct inode */
#include <linux/dcache.h>                                       /* struct dentry */
#include <linux/namei.h>                                        /* struct nameidata */

#define INODE struct inode
#define DENTRY struct dentry
#define IATTR struct iattr
#define NAMEIDATA struct nameidata

int fsmac_init(void);

void fsmac_cleanup(void);

int inode_create_hook(INODE *inode, DENTRY *dentry, int mask);
 
int inode_link_hook(DENTRY *src_dentry, INODE *inode, DENTRY *target_dentry);

int inode_unlink_hook(INODE *inode, DENTRY *dentry);

int inode_symlink_hook(INODE *inode, DENTRY *dentry, const char *name);

int inode_mkdir_hook(INODE *inode, DENTRY *dentry, int mask);

int inode_rmdir_hook(INODE *inode, DENTRY *dentry);

int inode_setattr_hook(DENTRY *dentry, IATTR *iattr);

int inode_access_hook(INODE *inode, int mask, NAMEIDATA *nd);

#endif
