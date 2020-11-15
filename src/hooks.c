#include <linux/kernel.h>                                       /* printk */
#include <linux/init.h>                                         /* init_ exit_ macros */
#include "hooks.h"
#include "procfs.h"
#include "ruleset.h"
#include "tasklabel.h"
#include "capability.h"
#include "fsmac.h"
#include "netmac.h"
#include "utils.h"
#include "dummy_ops.c"

/* cd /usr/src/kernels/2.6.18-238.19.1.el5-i686 */
/* make M=/data/projects/c/exeguard/ */

static SECURITY_OPERATIONS security_handler =
{
    // Hooked by tasklabel module
    .bprm_alloc_security = bprm_alloc_security_hook,
    .task_alloc_security = task_alloc_security_hook,
    .task_free_security = task_free_security_hook,
    .getprocattr = getprocattr_hook,
    .setprocattr = setprocattr_hook,
    // Hooked by capability module
    .ptrace = ptrace_hook,
    .capable = capable_hook,
    // Hooked by fsmac module
    .inode_create = inode_create_hook,
    .inode_link = inode_link_hook,
    .inode_unlink = inode_unlink_hook,
    .inode_symlink = inode_symlink_hook,
    .inode_mkdir = inode_mkdir_hook,
    .inode_rmdir = inode_rmdir_hook,
    .inode_setattr = inode_setattr_hook,
    .inode_permission = inode_access_hook,
    #ifdef CONFIG_SECURITY_NETWORK
    // Hooked by netmac module
    .socket_connect = socket_connect_hook,
    .socket_bind = socket_bind_hook,
    .socket_accept = socket_accept_hook,
    #endif
};

SECURITY_OPERATIONS secondary_ops;

int __init rainmac_init(void)
{
    int ret = 0;
    if (!ret)
    {
        ret = procfs_init();
    }
    if (!ret)
    {
        ret = ruleset_init();
    }
    if (!ret)
    {
        ret = tasklabel_init();
    }
    if (!ret)
    {
        ret = capability_init();
    }
    if (!ret)
    {
        ret = fsmac_init();
    }
    if (!ret)
    {
        ret = netmac_init();
    }
    if (ret)
    {
        netmac_cleanup();
        fsmac_cleanup();
        capability_cleanup();
        tasklabel_cleanup();
        ruleset_cleanup();
        procfs_cleanup();
        return ret;
    }
    secondary_ops = *security_ops;
    security_fixup_ops(&security_handler); 
    *security_ops = security_handler;
    printk(KERN_INFO MODULE_NAME": loaded\n");
    return 0;
}

void __exit rainmac_cleanup(void)
{
    *security_ops = secondary_ops;
    netmac_cleanup();
    fsmac_cleanup();
    capability_cleanup();
    tasklabel_cleanup();
    ruleset_cleanup();
    procfs_cleanup();
    printk(KERN_INFO MODULE_NAME": unloaded\n");
}

module_init(rainmac_init);
module_exit(rainmac_cleanup);
