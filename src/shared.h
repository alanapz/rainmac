#ifndef SHARED_H
#define	SHARED_H

#include <linux/sched.h>                                        /* struct task_struct, struct group_info */
#include <linux/security.h>                                     /* struct security_operations */

// Struct aliases

#define TASK struct task_struct

#define SECURITY_OPERATIONS struct security_operations

#define GROUP_INFO struct group_info

// Constants

#define MODULE_NAME "rainmac"

#endif
