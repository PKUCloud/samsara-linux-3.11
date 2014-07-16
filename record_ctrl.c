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

#define KVMIO 0xAE
#define KVM_ENABLE_RECORD         _IO(KVMIO, 0x09)
#define KVM_DISABLE_RECORD        _IO(KVMIO, 0x0a)
#define KVM_GET_API_VERSION       _IO(KVMIO,   0x00)

#define KVM_RECORD_PREEMPTION 0
#define KVM_RECORD_TIMER 1
#define KVM_RECORD_UNSYNC_PREEMPTION 2
#define KVM_RECORD_MAX_TYPE 3

#define KVM_RECORD_SOFTWARE 0
#define KVM_RECORD_HARDWARE_WALK_MMU 1
#define KVM_RECORD_HARDWARE_WALK_MEMSLOT 2
#define KVM_RECORD_MAX_MODE 3

#define LOGGER_IOC_MAGIC 0XAF
#define LOGGER_FLUSH	_IO(LOGGER_IOC_MAGIC, 0)


/**
*fname: the file name of the device to map
*fname_log: the output file name of the log
*/
void log2file(const char *fname, const char *fname_log)
{
	FILE *f;
	FILE *f_log;
	unsigned long offset = 0, len = 4096;
	void *address = (void*)-1;
	char *str;
	int i;
	int result;
	char buf[4096];

	//open the file to map
	if(!(f = fopen(fname, "r"))) {
		fprintf(stderr, "Fail to open %s: %s\n", fname, strerror(errno));
		exit(1);
	}

	//open the file to write the log into
	if(!(f_log = fopen(fname_log, "w"))) {
		fprintf(stderr, "Fail to open %s to write into: %s\n", fname_log, strerror(errno));
		exit(1);
	}

	printf("Logging...\n"
		"Use flush command to stop logging\n");
	//i = 0;
	while(1) {
		//i++;
		//mmap
		result = fread(buf, 1, len, f);

		if(result != len) {
			//the kernel has flushed the data

			if(feof(f)) {
				//now data is in buf
				if(fwrite(buf, 1, result, f_log) != result){
					fprintf(stderr, "fwrite() %s fail:%s\n", fname_log, strerror(errno));
					fclose(f);
					fclose(f_log);
					exit(1);
				}

				break;   //finish
			}else {
				//error
				fprintf(stderr, "fread file %s error:%s\n", fname, strerror(errno));
				fclose(f);
				fclose(f_log);
				exit(1);
			}
		}

		//now mmap and read the data
		address = mmap(0, len, PROT_READ, MAP_LOCKED | MAP_SHARED, fileno(f), offset);
		if(address == (void *)-1) {
			fprintf(stderr, "mmap() file%s error:%s\n",fname, strerror(errno));
			fclose(f);
			fclose(f_log);
			exit(1);
		}
			
		//output the log to fname_log
		str = (char*)address;

		//fprintf(f_log, "<start>==========\n");

		if(fwrite(str, len, 1, f_log) != 1){
			fprintf(stderr, "fwrite() %s fail:%s\n", fname_log, strerror(errno));
			fclose(f);
			fclose(f_log);
			exit(1);
		}
		//fprintf(f_log, "\n<end>============\n");
		fflush(f_log);
		//the driver will delete the data that mapped currently
		//so when we map the same address next time, it will actually be the next page
		munmap(address, len);

		address = (void *)-1;
	}

	printf("Logs has been written into file %s\n", fname_log);
	fclose(f);
	fclose(f_log);
}

struct {
	int type;
	char *name;
} kvm_record_arg[] = 
{ {KVM_RECORD_PREEMPTION, "PREEMPTION"},
  {KVM_RECORD_TIMER, "TIMER"},
  {KVM_RECORD_UNSYNC_PREEMPTION, "UNSYNC_PREEMPTION"}
};

struct {
	int type;
	char *name;
} kvm_record_mode[] =
{ {KVM_RECORD_SOFTWARE, "SOFT"},
  {KVM_RECORD_HARDWARE_WALK_MMU, "HARD_MMU"},
  {KVM_RECORD_HARDWARE_WALK_MEMSLOT, "HARD_MEMSLOT"},
};

struct kvm_record_ctrl {
	int kvm_record_type;
	unsigned kvm_record_timer_value;
	int kvm_record_mode;
	int print_log;
	int separate_mem;
};

int help() {
	fprintf(stderr, "Usage: \n"
			"record_ctrl <enable/disable> <record_type> <value> <log_file> [<record_mode> <print_log> <separate_memory>]\n"
			"\t<record_type> : PREEMPTION, UNSYNC_PREEMPTION, TIMER\n"
			"\t<record_mode> : SOFT, HARD_MMU, HARD_MEMSLOT; default is SOFT\n"
			"\t<print_log> : ON/OFF, default is on\n"
			"\t<separate_memory> : ON/OFF, default is OFF; valid only under HARD_MMU\n"
			"record_ctrl flush\n"
			"\tFlushes all the data out to the <log_file>. This will stop writting more data\n"
			"\tto the logger module and flush all the remaining data out to the <log_file>. \n"
			"\tAfter that the record_ctrl will stop working and return. This command is normally\n"
			"\tused when the virtual machine has been shutdown.\n"
			"record_ctrl clean\n"
			"\tDelete all the data in the logger module and sotp the record_ctrl program working in\n"
			"\tthe userspace(if any).!NOT IMPLEMENTED YET!\n"
			"record_ctrl help\n"
			"\tDisplay the help infomation.\n");
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
			return -1;
		}
		return 0;
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

	if(strcmp(argv[1], "flush") == 0) {
		//flush the logger
		return flush();
	} else if(strcmp(argv[1], "clean") == 0) {
		//clean all the data in the logger and stop swapping to file
		printf("record_ctrl clean not implemented yet\n");
		return 0;
	}else if(strcmp(argv[1], "help") == 0) {
		//print help info
		return help();
	}

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
		char *fname_log = "kern.log";

		if (argc < 5)
			return help();

		fname_log = argv[4];

		kvm_rc.kvm_record_type = -1;
		for (i=0; i<KVM_RECORD_MAX_TYPE; i++)
			if (strcmp(argv[2], kvm_record_arg[i].name) == 0)
				kvm_rc.kvm_record_type = kvm_record_arg[i].type;
		if (kvm_rc.kvm_record_type < 0) {
			fprintf(stderr, "Unknow record type : %s\n", argv[2]);
			return help();
		}
		sscanf(argv[3], "%u", &(kvm_rc.kvm_record_timer_value));
		kvm_rc.kvm_record_mode = KVM_RECORD_SOFTWARE;
		if (argc >= 6)
			for (i=0; i<KVM_RECORD_MAX_MODE; i++)
				if (strcmp(argv[5], kvm_record_mode[i].name) == 0)
					kvm_rc.kvm_record_mode = kvm_record_mode[i].type;
		kvm_rc.print_log = 1;
		if (argc >= 7)
			if (strcmp(argv[6], "OFF") == 0 || strcmp(argv[6], "off") == 0)
				kvm_rc.print_log = 0;

		kvm_rc.separate_mem = 0;
		if (argc >= 8)
			if (strcmp(argv[7], "ON") == 0 || strcmp(argv[7], "on") == 0) {
				if (kvm_rc.kvm_record_mode == KVM_RECORD_HARDWARE_WALK_MMU)
					kvm_rc.separate_mem = 1;
				else
					fprintf(stderr, "Can't turn on separate_memory under this mode\n");
			}
		printf("separate_mem=%d\n", kvm_rc.separate_mem);
		
		ret = ioctl(fd, KVM_ENABLE_RECORD, &kvm_rc);
		if (ret < 0) {
			printf("KVM_ENABLE_RECORD failed, errno = %d\n"
				"Please disable kvm_record fisrt if enabled.\n", errno);
			return -1;
		}
		printf("KVM_ENABLE_RECORD, type = %s, val = %u\n", argv[2], kvm_rc.kvm_record_timer_value);

		//record to file
		log2file("/dev/logger", fname_log);

	} else {
		ret = ioctl(fd, KVM_DISABLE_RECORD, 0);
		if (ret < 0)
			printf("KVM_DISABLE_RECORD failed, errno = %d\n", errno);
		printf("KVM_DISABLE_RECORD\n");
	}
	return 0;
}
