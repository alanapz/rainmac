#include "iobuff.h"
#include <linux/module.h>                                   /* kmalloc etc */

// Forward declarations

static void resize_iobuff(IOBUFF*, int);

// Definitions

IOBUFF* alloc_iobuff(void)
{
    IOBUFF* buff = kmalloc(sizeof(IOBUFF), GFP_KERNEL);
    buff->pos = 0;
    buff->cap = 256;
    buff->data = kmalloc(buff->cap, GFP_KERNEL);
    return buff;
}

void release_iobuff(IOBUFF *buff)
{
    kfree(buff->data);
    kfree(buff);
}

void iobuff_write_str(IOBUFF *buff, const char *val)
{
    iobuff_write_data(buff, val, strlen(val) + 1); // +1 for trailing null
}

void iobuff_write_chars(IOBUFF *buff, const char *val)
{
    iobuff_write_data(buff, val, strlen(val));
}

void iobuff_write_data(IOBUFF *buff, const char *val, int len)
{
    resize_iobuff(buff, len);
    memcpy(&buff->data[buff->pos], val, len);
    buff->pos += len;
}

void iobuff_write_null(IOBUFF *buff)
{
    resize_iobuff(buff, 1);
    buff->data[buff->pos++] = '\0';
}

void iobuff_write_char(IOBUFF *buff, char val)
{
    resize_iobuff(buff, 1);
    buff->data[buff->pos++] = val;
}

void iobuff_write_int2(IOBUFF *buff, int val)
{
    resize_iobuff(buff, 2);
    buff->data[buff->pos++] = val >> 8;
    buff->data[buff->pos++] = val & 0xff;
}

void iobuff_write_long4(IOBUFF *buff, long val)
{
    resize_iobuff(buff, 4);
    buff->data[buff->pos++] = val >> 24;
    buff->data[buff->pos++] = val >> 16;
    buff->data[buff->pos++] = val >> 8;
    buff->data[buff->pos++] = val & 0xff;
}

void iobuff_sprintf(IOBUFF* buff, const char* format, ...)
{
    #define BUFFSIZE 1024
    va_list args;
    char *val = kmalloc(BUFFSIZE, GFP_KERNEL);
    va_start(args, format);
    int len = vsnprintf(val, BUFFSIZE, format, args);
    va_end(args);
    #undef BUFFSIZE
    resize_iobuff(buff, ++len); // Remember +1 for null
    memcpy(&buff->data[buff->pos], val, len);
    buff->pos += len;
}

void iobuff_csprintf(IOBUFF* buff, const char* format, ...)
{
    #define BUFFSIZE 1024
    va_list args;
    char *val = kmalloc(BUFFSIZE, GFP_KERNEL);
    va_start(args, format);
    int len = vsnprintf(val, BUFFSIZE, format, args);
    va_end(args);
    #undef BUFFSIZE
    resize_iobuff(buff, len);
    memcpy(&buff->data[buff->pos], val, len);
    buff->pos += len;
}

static void resize_iobuff(IOBUFF *buff, int additional)
{
    while (buff->pos + additional > buff->cap)
    {
        char* prev_data = buff->data;;
        int prev_cap = buff->cap;
        buff->cap *= 2;
        buff->data = kmalloc(buff->cap, GFP_KERNEL);
        memcpy(buff->data, prev_data, prev_cap);
        kfree(prev_data);
    }
}
