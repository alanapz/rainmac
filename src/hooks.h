#ifndef HOOKS_H
#define	HOOKS_H

#include <linux/module.h>
#include "shared.h"

MODULE_VERSION("1.2011.09.25");
MODULE_AUTHOR("Alan Pinder <alan@alanpinder.com>");
MODULE_LICENSE("GPL");

int rainmac_init(void);

void rainmac_cleanup(void);

#endif
