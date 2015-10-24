#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <linux/types.h>
#include <stdlib.h>
#include <termios.h>
#include <limits.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <memory.h>

/* Definitions for KVM fd. Shoud be synchronized with
 * include/uapi/linux/kvm.h
 */
#define KVMIO				0xAE
#define KVM_RR_CTRL			_IO(KVMIO, 0x09)

/* Decide how to get accessed memory */
#define KVM_RR_CTRL_MEM_MASK		0x7U
#define KVM_RR_CTRL_MEM_SOFTWARE	0x0U
#define KVM_RR_CTRL_MEM_EPT		0x1U
#define KVM_RR_CTRL_MEM_MEMSLOT		0x2U

/* Decide record and replay mode */
#define KVM_RR_CTRL_MODE_MASK		(0x3U << 3)
#define KVM_RR_CTRL_MODE_SYNC		0x0U
#define KVM_RR_CTRL_MODE_ASYNC		(0x1U << 3)

/* Decide how to kick vcpu */
#define KVM_RR_CTRL_KICK_MASK		(0x3U << 5)
#define KVM_RR_CTRL_KICK_PREEMPTION	0x0U
#define KVM_RR_CTRL_KICK_TIMER		(0x1U << 5)

struct kvm_rr_ctrl {
	__u16 enabled;
	__u16 ctrl;
	__u32 timer_value;
};

/* Definitions for logger fd */
#define LOGGER_IOC_MAGIC		0XAF
#define LOGGER_FLUSH			_IO(LOGGER_IOC_MAGIC, 0)

struct arg_desc {
	int id;
	char *name;
};

struct arg_desc RR_CTRL_MEM[] = {
	{KVM_RR_CTRL_MEM_SOFTWARE, "SOFTWARE"},
	{KVM_RR_CTRL_MEM_EPT, "EPT"},
	{KVM_RR_CTRL_MEM_MEMSLOT, "MEMSLOT"},
};

struct arg_desc RR_CTRL_MODE[] = {
	{KVM_RR_CTRL_MODE_SYNC, "SYNC"},
	{KVM_RR_CTRL_MODE_ASYNC, "ASYNC"},
};

struct arg_desc RR_CTRL_KICK[] = {
	{KVM_RR_CTRL_KICK_PREEMPTION, "PREEMPTION"},
	{KVM_RR_CTRL_KICK_TIMER, "TIMER"},
};

/*
 * @fname: the file name of the device to map
 * @fname_log: the output file name of the log
 */
int log2file(const char *fname, const char *fname_log)
{
	FILE *f;
	FILE *f_log;
	unsigned long offset = 0, len = 4096;
	void *address = (void*)-1;
	char *str;
	int result;
	char buf[4096];

	/* Open the file to map */
	if(!(f = fopen(fname, "r"))) {
		fprintf(stderr, "Fail to open %s: %s\n", fname, strerror(errno));
		return -1;
	}

	/* Open the file to write the log into */
	if(!(f_log = fopen(fname_log, "w"))) {
		fprintf(stderr, "Fail to open %s to write into: %s\n", fname_log, strerror(errno));
		return -1;
	}

	printf("Start logging. Use flush command to stop it.\n");
	while(1) {
		/* Mmap */
		result = fread(buf, 1, len, f);
		if(result != len) {
			/* The kernel has flushed the data */
			if(feof(f)) {
				/* Now data are in buf */
				if(fwrite(buf, 1, result, f_log) != result){
					fprintf(stderr, "fwrite() %s fail:%s\n", fname_log, strerror(errno));
					fclose(f);
					fclose(f_log);
					exit(1);
				}
				/* Finish */
				break;
			}else {
				fprintf(stderr, "fread file() %s error:%s\n", fname, strerror(errno));
				fclose(f);
				fclose(f_log);
				return -1;
			}
		}

		/* Mmap and read the data */
		address = mmap(0, len, PROT_READ, MAP_LOCKED | MAP_SHARED, fileno(f), offset);
		if(address == (void *)-1) {
			fprintf(stderr, "mmap() %s error:%s\n",fname, strerror(errno));
			fclose(f);
			fclose(f_log);
			return -1;
		}

		/* Output the log to fname_log */
		str = (char*)address;
		if(fwrite(str, len, 1, f_log) != 1){
			fprintf(stderr, "fwrite() %s fail:%s\n", fname_log, strerror(errno));
			fclose(f);
			fclose(f_log);
			return -1;
		}

		/* The driver will delete the data that mapped currently,
		 * so when we map the same address next time, it will
		 * actually be the next page.
		 */
		munmap(address, len);
		address = (void *)-1;
	}

	printf("Logged into file %s\n", fname_log);
	fclose(f);
	fclose(f_log);
	return 0;
}

int help()
{
	fprintf(stderr, "Usage: \n"
			"record_ctrl <enable/disable> <mode> <kick> <mem> <value> [log_file]\n"
			"\t<mode>: SYNC, ASYNC\n"
			"\t<kick>: PREEMPTION, TIMER\n"
			"\t<mem>: SOFTWARE, EPT, MEMSLOT\n"
			"\t[log_file]: the name of the log; default is \"kern.log\"\n"
			"\n"
			"record_ctrl flush\n"
			"\tFlushes all the data out to the <log_file>. This will stop writting more data\n"
			"\tto the logger module and flush all the remaining data out to the <log_file>. \n"
			"\tAfter that the record_ctrl will stop working and return. This command is normally\n"
			"\tused after the virtual machine being shutdowned.\n"
			"record_ctrl help\n"
			"\tDisplay this help information.\n");
	return -1;
}

int flush(void)
{
	int fd_logger;
	int ret;

	fd_logger = open("/dev/logger", 0);
	if(fd_logger < 0) {
		printf("Open /dev/logger failed\n");
		return -1;
	}
	ret = ioctl(fd_logger, LOGGER_FLUSH);
	if(ret < 0) {
		printf("Flush failed\n");
	}
	close(fd_logger);
	return ret;
}

int parseArg(struct arg_desc options[], int n, char *arg)
{
	int i;

	for (i = 0; i < n; ++i) {
		if (strcmp(arg, options[i].name) == 0) {
			return options[i].id;
		}
	}
	return -1;
}

int main(int argc, char **argv)
{
	int record;
	struct kvm_rr_ctrl rr_ctrl;
	int ret;
	int i;
	int kvm_fd;

	if (argc < 2)
		return help();

	if(strcmp(argv[1], "flush") == 0) {
		return flush();
	} else if(strcmp(argv[1], "help") == 0) {
		return help();
	}

	if (strcmp(argv[1], "enable") == 0)
		record = 1;
	else if (strcmp(argv[1], "disable") == 0)
		record = 0;
	else {
		fprintf(stderr, "Unknow command : %s\n", argv[1]);
		return help();
	}

	memset(&rr_ctrl, 0, sizeof(rr_ctrl));

	kvm_fd = open("/dev/kvm", 0);
	if (kvm_fd < 0) {
		fprintf(stderr, "Fail to open /dev/kvm\n");
		return -1;
	}

	if (record) {
		const char *fname_log = "kern.log";

		if (argc < 6) {
			ret = -1;
			help();
			goto out;
		}
		if(argc == 7) {
			fname_log = argv[6];
		}
		printf("Log: %s\n", fname_log);

		rr_ctrl.enabled = 1;

		// Get mode
		ret = parseArg(RR_CTRL_MODE,
			       sizeof(RR_CTRL_MODE) / sizeof(struct arg_desc),
			       argv[2]);
		if (ret == -1) {
			fprintf(stderr, "Unknown mode: %s\n", argv[2]);
			help();
			goto out;
		} else {
			printf("Mode: %s[%d]\n", argv[2], ret);
			rr_ctrl.ctrl |= ret;
		}

		// Get kick
		ret = parseArg(RR_CTRL_KICK,
			       sizeof(RR_CTRL_KICK) / sizeof(struct arg_desc),
			       argv[3]);
		if (ret == -1) {
			fprintf(stderr, "Unknown kick: %s\n", argv[3]);
			help();
			goto out;
		} else {
			printf("Kick: %s[%d]\n", argv[3], ret);
			rr_ctrl.ctrl |= ret;
		}

		// Get mem
		ret = parseArg(RR_CTRL_MEM,
			       sizeof(RR_CTRL_MEM) / sizeof(struct arg_desc),
			       argv[4]);
		if (ret == -1) {
			fprintf(stderr, "Unknown mem: %s\n", argv[4]);
			help();
			goto out;
		} else {
			printf("Mem: %s[%d]\n", argv[4], ret);
			rr_ctrl.ctrl |= ret;
		}

		// Get value
		ret = -1;
		sscanf(argv[5], "%u", &ret);
		if (ret == -1) {
			fprintf(stderr, "Unknown value: %s\n", argv[5]);
			help();
			goto out;
		} else {
			printf("Value: %d\n", ret);
			rr_ctrl.timer_value = ret;
		}

		printf("Ctrl: 0x%x\n", rr_ctrl.ctrl);

		ret = ioctl(kvm_fd, KVM_RR_CTRL, &rr_ctrl);
		if (ret < 0) {
			fprintf(stderr, "Fail to enable recording: %s\n",
				strerror(errno));
			goto out;
		}
		printf("Recording enabled\n");
		ret = log2file("/dev/logger", fname_log);
	} else {
		// Disable record and replay
		rr_ctrl.enabled = 0;
		ret = ioctl(kvm_fd, KVM_RR_CTRL, &rr_ctrl);
		if (ret < 0) {
			fprintf(stderr, "Fail to disable recording: %s\n",
				strerror(errno));
		} else {
			printf("Recording disabled\n");
		}
		ret = 0;
	}

out:
	close(kvm_fd);
	return ret;
}
