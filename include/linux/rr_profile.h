#ifndef __RR_PROFILE_H
#define __RR_PROFILE_H


// Profile Switch
#define RR_PROFILE
//#define RR_PROFILE_CONFLICT

#ifdef RR_PROFILE
#define PROFILE_BEGIN(v)   {uint64_t v##_val = rr_rdtsc();
#define PROFILE_END(v)     vcpu->rr_states.profile_##v += calculate_tsc(v##_val);}
#define PROFILE_CALCULATE(v) kvm->vcpus[0]->rr_states.profile_##v += \
                             kvm->vcpus[i]->rr_states.profile_##v;
#define PROFILE_PRINT(v)     printk(KERN_ERR "PROFILE - "#v"=%llu\n", vcpu->rr_states.profile_##v);
#else
#define PROFILE_BEGIN(v) {}
#define PROFILE_END(v) {}
#define PROFILE_CALCULATE(v) {}
#define PROFILE_PRINT(v) {}
#endif

// 2G mem is 2G/4K=512K
// 500M mem is 128K
#define TM_BITMAP_SIZE 1024*1024

/* If defined, use Binary exponential backoff to decide next chunk's preemption
 * timer value.
 */
// #define RR_BEBACKOFF

#ifdef RR_BEBACKOFF

#define RR_CONSEC_RB_TIME 4
#define RR_BEBACKOFF_START_RB_TIME 1
#define RR_BEASCEND_START_CM_TIME 1
#define RR_BEBACKOFF_MINM 100UL
#define RR_BEBACKOFF_LINE 1000UL

#else

#define RR_CONSEC_RB_TIME 3

#endif

// Optimizations
#define RR_AD_BIT_OPT
/* Early rollback and early check is exclusive */
//#define RR_EARLY_ROLLBACK
#define RR_EARLY_CHECK

/* If defined, we use the vcpu.arch.holding_pages to hold a list of pages that
 * have been COW. We will not withdraw the write permission and free the private
 * pages until we have to.
 */
#define RR_HOLDING_PAGES
/* Maximum length of vcpu.arch.holding_pages list */
#define RR_HOLDING_PAGES_MAXM        512
#define RR_HOLDING_PAGES_TARGET_NR   256

/* If defined, we use a separate list to hold pages need to rollback and before
 * entering guest, we copy the new content of those pages.
 * BUG: If kvm read/write guest pages after we rollback while other vcpus haven't
 * finished commit yet, we may read old contents. This bug is introduced in the
 * commit adding kvm.chunk_list.
 */
#define RR_ROLLBACK_PAGES

struct vmexit_states {
	uint64_t num;
	uint64_t time;
};

struct vcpu_rr_states {
	uint64_t profile_total_commit_time;
	uint64_t profile_tm_lock_time, profile_tm_rwlock_time, profile_wait_time, profile_exclusive_time;
	uint64_t profile_detect_conflict_time, profile_set_dirty_time, profile_memory_time;
	uint64_t profile_clear_bitmap_time, profile_clear_dma_bitmap_time;
	uint64_t profile_walk_mmu_time;
				
	int exit_reason;
};

static inline uint64_t rr_rdtsc(void)
{
	unsigned int low, high;

	asm volatile("rdtsc" : "=a" (low), "=d" (high));

	return low | ((unsigned long long)high) << 32;
}

static inline uint64_t calculate_tsc(uint64_t val)
{
       uint64_t tsc = rr_rdtsc();
       if (tsc < val) {
               return 0xffffffffffffffffUL - val + tsc;
       }
       else
               return tsc - val;
}

#endif
