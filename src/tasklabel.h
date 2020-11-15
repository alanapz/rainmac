#ifndef TASKLABEL_H
#define	TASKLABEL_H

#include <linux/binfmts.h>                                      /* struct linux_binprm */
#include "shared.h"

#define LINUX_BINPRM struct linux_binprm

int tasklabel_init(void);

void tasklabel_cleanup(void);

int bprm_alloc_security_hook(LINUX_BINPRM *bprm);

int task_alloc_security_hook(TASK *p);

void task_free_security_hook(TASK *p);

int getprocattr_hook(TASK *p, char *name, void *value, size_t size);

int setprocattr_hook(TASK *p, char *name, void *value, size_t size);

/*
 * Returns the RM label of the specified task
 * This is a copy, which the caller must kfree
 */
const char* lookup_task_label(const TASK *task);

#endif
