ifneq ($(KERNELRELEASE),)
	obj-m := logger.o
	logger-objs := logger_main.o mmap.o

else

KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)


modules:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules
endif


clean:
	rm -rf *.o *.ko *.mod.c