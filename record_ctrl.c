#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <linux/types.h>

#define KVMIO 0xAE
#define KVM_ENABLE_RECORD         _IO(KVMIO, 0x09)
#define KVM_DISABLE_RECORD        _IO(KVMIO, 0x0a)
#define KVM_GET_API_VERSION       _IO(KVMIO,   0x00)

#define KVM_RECORD_PREEMPTION 0
#define KVM_RECORD_TIMER 1
#define KVM_RECORD_UNSYNC_PREEMPTION 2
#define KVM_RECORD_MAX_TYPE 3

struct {
	int type;
	char *name;
} kvm_record_arg[] = 
{ {KVM_RECORD_PREEMPTION, "PREEMPTION"},
  {KVM_RECORD_TIMER, "TIMER"},
  {KVM_RECORD_UNSYNC_PREEMPTION, "UNSYNC_PREEMPTION"}
};

struct kvm_record_ctrl {
	int kvm_record_type;
	unsigned kvm_record_timer_value;
};

int help() {
	fprintf(stderr, "Usage: record_ctrl <enable/disable> <record_type> <value>\n"
			"\t<record_type> : PREEMPTION, UNSYNC_PREEMPTION, TIMER\n");
	return -1;
}

int main(int argc, char **argv)
{
	int fd;
	int record;
	int ret;
	long type;
	unsigned long val;
	char cmd[256];
	struct kvm_record_ctrl kvm_rc;
	int i;

	if (argc < 2)
		return help();

	fd = open("/dev/kvm", 0);
	if (fd < 0) {
		printf("Open /dev/kvm failed\n");
		return -1;
	}
	if (strcmp(argv[1], "enable") == 0)
		record = 1;
	else if (strcmp(argv[1], "disable") == 0)
		record = 0;
	else {
		fprintf(stderr, "Unknow command : %s\n", argv[1]);
		return help();
	}

	if (record) {
		if (argc < 4)
			return help();
		kvm_rc.kvm_record_type = -1;
		for (i=0; i<KVM_RECORD_MAX_TYPE; i++)
			if (strcmp(argv[2], kvm_record_arg[i].name) == 0)
				kvm_rc.kvm_record_type = kvm_record_arg[i].type;
		if (kvm_rc.kvm_record_type < 0) {
			fprintf(stderr, "Unknow record type : %s\n", argv[2]);
			return help();
		}
		sscanf(argv[3], "%u", &(kvm_rc.kvm_record_timer_value));
		ret = ioctl(fd, KVM_ENABLE_RECORD, &kvm_rc);
		if (ret < 0) {
			printf("KVM_ENABLE_RECORD failed, errno = %d\n"
				"Please disable kvm_record fisrt if enabled.\n", errno);
			return -1;
		}
		printf("KVM_ENABLE_RECORD, type = %s, val = %u\n", argv[2], kvm_rc.kvm_record_timer_value);
	} else {
		ret = ioctl(fd, KVM_DISABLE_RECORD, 0);
		if (ret < 0)
			printf("KVM_DISABLE_RECORD failed, errno = %d\n", errno);
		printf("KVM_DISABLE_RECORD\n");
	}
	return 0;
}
