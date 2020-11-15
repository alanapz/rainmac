#ifndef PROCFS_H
#define	PROCFS_H

#include "shared.h"
#include "utils.h"

typedef void PROCDATA;
typedef void TAGDATA;

int procfs_init(void);

void procfs_cleanup(void);

const PROCDATA* create_procfile(const char* name, int mode, TAGDATA*, void (*user_read)(IOBUFF*, TAGDATA*), int (*user_write)(IOBUFF*, TAGDATA*));

void remove_procfile(const PROCDATA*);

#endif
