#ifndef CAPABILITY_H
#define	CAPABILITY_H

#include "shared.h"

int capability_init(void);

void capability_cleanup(void);

int ptrace_hook(struct task_struct *parent, struct task_struct *child);

int capable_hook(TASK *task, int cap);

#endif
