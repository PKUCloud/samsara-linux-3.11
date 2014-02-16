#ifndef ARCH_X86_KVM_LOG_UTIL_H
#define ARCH_X86_KVM_LOG_UTIL_H

#include <linux/module.h>


/*
*usage:
	if(log_util_mod && try_module_get(log_util_mod)) {
		(*print_record_ptr)("Hello, I am tamlok\n");
		(*print_record_ptr)("Hello, I %%am %s\n", "tam lok");
		(*print_record_ptr)("Hello, I am %c\n", 'a');
		(*print_record_ptr)("Hello, count is %6.3ld\n", loc);
		(*print_record_ptr)("Hello, it is %010X", 233321);
		module_put(log_util_mod);
	}
*/
	
static struct module *log_util_mod;
EXPORT_SYMBOL(log_util_mod);

static int (*print_record_ptr)(const char *fmt, ...);
EXPORT_SYMBOL(print_record_ptr);

#endif
