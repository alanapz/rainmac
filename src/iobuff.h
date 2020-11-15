#ifndef IOBUFF_H
#define	IOBUFF_H

#define IOBUFF struct iobuff

struct iobuff
{
    int pos;
    int cap;
    char *data;
};

IOBUFF* alloc_iobuff(void);

void release_iobuff(IOBUFF*);

void iobuff_write_str(IOBUFF*, const char*);

void iobuff_write_chars(IOBUFF*, const char*);

void iobuff_write_data(IOBUFF*, const char*, int len);

void iobuff_write_null(IOBUFF*);

void iobuff_write_char(IOBUFF*, char);

void iobuff_write_int2(IOBUFF*, int);

void iobuff_write_long4(IOBUFF*, long);

void iobuff_sprintf(IOBUFF*, const char*, ...) __attribute__ ((format (printf, 2, 3)));

// Does not append trailing null
void iobuff_csprintf(IOBUFF*, const char*, ...) __attribute__ ((format (printf, 2, 3)));

#endif
