#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <errno.h>

#define KVMIO 0xAE
#define KVM_ENABLE_RECORD         _IO(KVMIO, 0x09)
#define KVM_DISABLE_RECORD        _IO(KVMIO, 0x0a)
#define KVM_GET_API_VERSION       _IO(KVMIO,   0x00)

int main(int argc, char **argv)
{
	int fd;
	int record;
	int ret;
	long type;
	unsigned long val;
	fd = open("/dev/kvm", 0);
	if (fd < 0) {
		printf("Open /dev/kvm failed\n");
		return -1;
	}
	if (argc < 2) {
		record = 1;
	} else {
		if (strcmp(argv[1], "enable") == 0)
			record = 1;
		else
			record = 0;
	}
	if (argc > 2)
		sscanf(argv[2], "%lu", &val);
	else
		val = 0;
	if (record) {
		ret = ioctl(fd, KVM_ENABLE_RECORD, val);
		if (ret < 0)
			printf("KVM_ENABLE_RECORD failed, errno = %d\n", errno);
		printf("KVM_ENABLE_RECORD, preemption val = %lu\n", val);
	} else {
		ret = ioctl(fd, KVM_DISABLE_RECORD, 0);
		if (ret < 0)
			printf("KVM_DISABLE_RECORD failed, errno = %d\n", errno);
		printf("KVM_DISABLE_RECORD\n");
	}
	return 0;
}
