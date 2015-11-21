#ifndef __RECORD_REPLAY_H
#define __RECORD_REPLAY_H

#include <linux/kvm.h> /* ioctl definition */
#include <linux/bitops.h>
#include <linux/mutex.h>
#include <linux/list.h>
#include <linux/kvm_types.h>
#include <linux/region_bitmap.h>
#include <asm/checkpoint_rollback.h>

struct kvm;
struct kvm_vcpu;
struct kvm_lapic;

/* Macro switches */
/* Each bit in the bitmap represents one memory page.
 * 2G memory needs at least 2G/4k, that is 512 * 1024.
 * Should also change RE_BITMAP_SIZE in region_bitmap.h.
 */
#define RR_BITMAP_SIZE		(1024 * 1024)

/* Max consecutive rollback times before exclusive commit */
#define RR_CONSEC_RB_TIME	3

/* Early rollback and early check is exclusive */
/* #define RR_EARLY_ROLLBACK */
#define RR_EARLY_CHECK

/* If defined, we use the vcpu.rr_info.holding_pages to hold a list of pages
 * that have been COW. We will not withdraw the write permission and free
 * the private pages until we have to.
 */
#define RR_HOLDING_PAGES
/* Maximum length of vcpu.rr_info.holding_pages list */
#define RR_HOLDING_PAGES_MAXM        512
#define RR_HOLDING_PAGES_TARGET_NR   512

/* If defined, we use a separate list to hold pages needed to rollback and
 * before entering guest, we copy the new content of those pages.
 */
#define RR_ROLLBACK_PAGES

#define RR_ASYNC_PREEMPTION_EPT	(KVM_RR_CTRL_MEM_EPT | KVM_RR_CTRL_MODE_ASYNC |\
				 KVM_RR_CTRL_KICK_PREEMPTION)

#define RR_DEFAULT_PREEMTION_TIMER_VAL	30000

#define RR_CHUNK_COMMIT			0
#define RR_CHUNK_ROLLBACK		1
#define RR_CHUNK_SKIP			2

#define RR_REQ_CHECKPOINT		0
#define RR_REQ_COMMIT_AGAIN		1
#define RR_REQ_POST_CHECK		2

/* Macros for rr_chunk_info.state */
#define RR_CHUNK_STATE_IDLE		0
#define RR_CHUNK_STATE_BUSY		1
#define RR_CHUNK_STATE_FINISHED		2

struct rr_chunk_info {
	struct list_head link;
	int vcpu_id;
	int action;	/* RR_CHUNK_COMMIT or RR_CHUNK_ROLLBACK */
	int state;
};

struct rr_event {
	struct list_head link;
	int delivery_mode;
	int vector;
	int level;
	int trig_mode;
	unsigned long *dest_map;
};

/* Record and replay control info for a particular vcpu */
struct rr_vcpu_info {
	bool enabled;		/* State of record and replay */
	u32 timer_value;	/* Preemption timer value of this vcpu */
	unsigned long requests;	/* Requests bitmap */
	bool is_master;		/* Used for synchronization */
	struct list_head events_list;
	struct mutex events_list_lock;
	struct list_head commit_again_gfn_list;
	/* Bitmaps */
	struct region_bitmap access_bitmap;
	struct region_bitmap dirty_bitmap;
	struct region_bitmap conflict_bitmap_1;	/* Double buffers */
	struct region_bitmap conflict_bitmap_2;
	struct region_bitmap DMA_access_bitmap;
	struct region_bitmap *public_cb;	/* Public conflict bitmap */
	struct region_bitmap *private_cb;	/* Private conflict bitmap */

	int exclusive_commit; /* Whether vcpu is in exclusive commit state */
	int nr_rollback;	/* Number of continuous rollback */
	int check_dma;
	struct CPUX86State vcpu_checkpoint;
	struct rr_chunk_info chunk_info;
	struct list_head private_pages;
	int nr_private_pages;
	struct list_head holding_pages; /* For pages that have been COW before */
	int nr_holding_pages;
#ifdef RR_ROLLBACK_PAGES
	/* For pages that need to rollback */
	struct list_head rollback_pages;
	int nr_rollback_pages;
#endif
	bool tlb_flush;
};

/* Record and replay control info for kvm */
struct rr_kvm_info {
	/* State of record and replay. Will be set to true after all vcpus
	 * have enabled recording.
	 */
	bool enabled;
	atomic_t nr_sync_vcpus;
	atomic_t nr_fin_vcpus;
	struct mutex tm_lock;
	struct list_head chunk_list;
	spinlock_t chunk_list_lock;
	int  last_commit_vcpu;
	/* 1 if we can commit normally, otherwise someone is in exclusive
	 * commit status.
	 */
	atomic_t normal_commit;
	/* Id of the vcpu that just recorded in log */
	int last_record_vcpu;
	struct rw_semaphore tm_rwlock; /* Read/write lock for DMA and vcpus */
	/* Whether DMA is holding the tm_rwlock */
	bool dma_holding_sem;
	/* If someone is in exclusive commit, we can't check and commit
	 * normally, just wait on this queue.
	 */
	wait_queue_head_t exclu_commit_que;
};

struct rr_ops {
	void (*ape_vmx_setup)(u32 timer_value);
	void (*tlb_flush)(struct kvm_vcpu *vcpu);
	void (*ape_vmx_clear)(void);
	u32 (*get_vmx_exit_reason)(struct kvm_vcpu *vcpu);
};

/* Structure used for keeping info about cow  memory page */
struct rr_cow_page {
	struct list_head link;
	gfn_t gfn;
	pfn_t original_pfn;
	pfn_t private_pfn;
	u64 *sptep;	/*Pointer of the spte that references this pfn */
};

void rr_init(struct rr_ops *rr_ops);
void rr_vcpu_info_init(struct kvm_vcpu *vcpu);
void rr_kvm_info_init(struct kvm *kvm);
void rr_kvm_info_exit(struct kvm *kvm);
int rr_vcpu_enable(struct kvm_vcpu *vcpu);
void rr_vcpu_checkpoint(struct kvm_vcpu *vcpu);
void rr_vcpu_rollback(struct kvm_vcpu *vcpu);
void rr_commit_again(struct kvm_vcpu *vcpu);
void rr_post_check(struct kvm_vcpu *vcpu);
int rr_apic_accept_irq(struct kvm_lapic *apic, int delivery_mode,
		       int vector, int level, int trig_mode,
		       unsigned long *dest_map);
void rr_apic_reinsert_irq(struct kvm_vcpu *vcpu);
void rr_set_mmio_spte_mask(u64 mmio_mask);
int rr_check_chunk(struct kvm_vcpu *vcpu);
void rr_memory_cow(struct kvm_vcpu *vcpu, u64 *sptep, pfn_t pfn, gfn_t gfn);
void *rr_ept_gfn_to_kaddr(struct kvm_vcpu *vcpu, gfn_t gfn, int write);

static inline void rr_make_request(int req, struct rr_vcpu_info *rr_info)
{
	set_bit(req, &rr_info->requests);
}

static inline bool rr_check_request(int req, struct rr_vcpu_info *rr_info)
{
	return test_bit(req, &rr_info->requests);
}

static inline void rr_clear_request(int req, struct rr_vcpu_info *rr_info)
{
	clear_bit(req, &rr_info->requests);
}

static inline void rr_clear_all_request(struct rr_vcpu_info *rr_info)
{
	rr_info->requests = 0;
}
#endif
