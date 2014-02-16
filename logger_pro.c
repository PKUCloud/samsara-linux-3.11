#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <limits.h>
#include <termios.h>
#include <fcntl.h>



int kbhit(void)
{
	struct termios oldt, newt;
	int ch;
	int oldf;
	tcgetattr(STDIN_FILENO, &oldt);
	newt = oldt;
	newt.c_lflag &= ~(ICANON | ECHO);
	tcsetattr(STDIN_FILENO, TCSANOW, &newt);
	oldf = fcntl(STDIN_FILENO, F_GETFL, 0);
	fcntl(STDIN_FILENO, F_SETFL, oldf | O_NONBLOCK);
	ch = getchar();
	tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
	fcntl(STDIN_FILENO, F_SETFL, oldf);
	if(ch != EOF) {
		ungetc(ch, stdin);
		return 1;
	}
	return 0;
}

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
	int isfirst = 1;

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

	//一直循环输出log，检测到按键时退出
	printf("Press any key to exit...\n");
	//i = 0;
	while(!kbhit()) {
		//i++;
		//mmap
		//maybe fail because of there is no enough data in the driver, so try again and again
		while(!kbhit() && address == (void *)-1) {
			address = mmap(0, len, PROT_READ, MAP_FILE | MAP_LOCKED | MAP_PRIVATE, fileno(f), offset);
			if(address == (void *)-1 && isfirst) {
				//fprintf(stderr, "%s: mmap():%s\nMaybe there is no data in the device, trying again\n", fname, strerror(errno));
				isfirst = 0;
			}
		}

		if(address == (void *)-1) break;   //user press a key

		if(!isfirst) {
			//fprintf(stderr, "Working...\n");
			isfirst = 1;
		}
			
		/*
		fprintf(stderr, "mapped \"%s\" from %lu (0x%08lx) to %lu (0x%08lx)\n",
			fname, offset, offset, offset+len, offset+len);
		*/
		
		//output the log to fname_log
		str = (char*)address;

		//fprintf(f_log, "<start>==========\n");

		if(fwrite(str, len, 1, f_log) != 1){
			fprintf(stderr, "fwrite() %s fail:%s\n", fname_log, strerror(errno));
			exit(1);
		}

		//fprintf(f_log, "\n<end>============\n");
		//munmap()
		//the driver will delete the data that mapped currently
		//so when we map the same address next time, it will actually be the next page
		munmap(address, len);

		address = (void *)-1;
	}

	printf("Logs has been written into file %s\n", fname_log);
	fclose(f);
	fclose(f_log);
}

int main(int argc, char **argv)
{
	char *fname = "/dev/logger";
	char *fname_log = "kern.log";
	
	if(argc == 2)
		fname_log = argv[1];
	fprintf(stderr, "output: %s\n", fname_log);

	log2file(fname, fname_log);
	
	return 0;

}