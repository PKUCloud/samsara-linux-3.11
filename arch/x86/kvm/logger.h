#ifndef ARCH_X86_LOGGER_LOGGER_H
#define ARCH_X86_LOGGER_LOGGER_H

#include <linux/cdev.h>
#include <linux/spinlock.h>

#define LOGGER_MAJOR 0  //dynamic major by default

#define LOGGER_QUANTUM 4096   //use a quantum size of 4096

struct logger_quantum {
	void *data;            //pointer to a page
	struct logger_quantum *next;     //next listitem
};

struct logger_dev {
	struct logger_quantum *head;     //the head of the quantum list
	struct logger_quantum *tail;      //the tail of the quantum list
	size_t size;               // total size of data in the device
	char *str;         //the start of the free space in current page
	char *end;          //the end of current page
	int vmas;              //active mappings
	spinlock_t dev_lock;
	struct cdev cdev;
};

#define ZEROPAD	1		/* pad with zero */
#define SIGN	2		/* unsigned/signed long */
#define PLUS	4		/* show plus */
#define SPACE	8		/* space if plus */
#define LEFT	16		/* left justified */
#define SMALL	32		/* use lowercase in hex (must be 32 == 0x20) */
#define SPECIAL	64		/* prefix hex with "0x", octal with "0" */


#define assert(expr) \
        if(unlikely(!(expr))) {				        \
        printk(KERN_ERR "Assertion failed! %s,%s,%s,line=%d\n",	\
	#expr, __FILE__, __func__, __LINE__);		        \
        }

enum format_type {
	FORMAT_TYPE_NONE, /* Just a string part */
	FORMAT_TYPE_WIDTH,
	FORMAT_TYPE_PRECISION,
	FORMAT_TYPE_CHAR,
	FORMAT_TYPE_STR,
	FORMAT_TYPE_PTR,
	FORMAT_TYPE_PERCENT_CHAR,
	FORMAT_TYPE_INVALID,
	FORMAT_TYPE_LONG_LONG,
	FORMAT_TYPE_ULONG,
	FORMAT_TYPE_LONG,
	FORMAT_TYPE_UBYTE,
	FORMAT_TYPE_BYTE,
	FORMAT_TYPE_USHORT,
	FORMAT_TYPE_SHORT,
	FORMAT_TYPE_UINT,
	FORMAT_TYPE_INT,
	FORMAT_TYPE_NRCHARS,
	FORMAT_TYPE_SIZE_T,
	FORMAT_TYPE_PTRDIFF
};

struct printf_spec {
	u8	type;		/* format_type enum */
	u8	flags;		/* flags to number() */
	u8	base;		/* number base, 8, 10 or 16 only */
	u8	qualifier;	/* number qualifier, one of 'hHlLtzZ' */
	s16	field_width;	/* width of output field */
	s16	precision;	/* # of digits/chars */
};
 
int print_record(const char* fmt, ...);

#endif
