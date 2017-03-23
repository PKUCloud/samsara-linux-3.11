#ifndef _ASM_X86_LOGGER_H
#define _ASM_X86_LOGGER_H
#include <linux/printk.h>
#include <asm/bug.h>

extern int rr_log(const char* fmt, ...);
extern int rr_log_buf(const unsigned char *buf, int len);
extern struct logger_log *rr_fetch_log(int vcpu_id);
extern void rr_free_log(struct logger_log *log);

#define DEBUG_RECORD_REPLAY
/* Print the real log for record and replay */
#define RECORD_REPLAY_LOG

#ifdef DEBUG_RECORD_REPLAY
enum {
	RR_DB_GEN, RR_DB_INIT, RR_DB_MMU,
};
#define RR_DBBIT(x)	(1 << RR_DB_##x)
//static int rr_dbflags = RR_DBBIT(GEN) | RR_DBBIT(INIT) | RR_DBBIT(MMU);
static int rr_dbflags = RR_DBBIT(GEN);

#define RR_DLOG(what, fmt, ...) do { \
	if (rr_dbflags & RR_DBBIT(what)) { \
		rr_log("%s: " fmt "\n", __func__, \
		       ## __VA_ARGS__); } \
	} while (0)

#define RR_ASSERT(x) do { \
	if (unlikely(!(x))) { \
		pr_err("error: rr assertion failed! %s, %s, %s #%d\n", \
		       #x, __FILE__, __func__, __LINE__); \
		dump_stack(); } \
	} while (0)

#else
#define RR_DLOG(what, fmt, ...) do {} while (0)
#define RR_ASSERT(x) do {} while (0)
#endif

#ifdef RECORD_REPLAY_LOG
#define RR_LOG(fmt, ...) do { \
	rr_log(fmt, ## __VA_ARGS__); \
	} while (0)
#else
#define RR_LOG(fmt, ...) do {} while (0)
#endif

#define RR_ERR(fmt, ...) do { \
	pr_err("%s: " fmt "\n", __func__, \
	       ## __VA_ARGS__); \
	} while (0)

#endif

