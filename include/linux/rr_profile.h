#ifndef __RR_PROFILE_H
#define __RR_PROFILE_H


// Profile Switch
//#define RR_PROFILE

// 2G mem is 2G/4K=512K
// 500M mem is 128K
#define TM_BITMAP_SIZE 1024*1024

// Params
#define RR_CONSEC_RB_TIME 10

// Optimizations
#define RR_AD_BIT_OPT
#define RR_EARLY_ROLLBACK

struct vmexit_states {
	uint64_t num;
	uint64_t time;
};

struct vcpu_rr_states {
	uint64_t vm_time, kvm_time;
	uint64_t total_commit_time, page_commit_time;
	uint64_t walk_mmu_time, set_dirty_bit_time, detect_conflict_time;
	struct vmexit_states vmexit_states[60];
	int exit_reason;
};

static inline uint64_t rr_rdtsc(void)
{
	unsigned int low, high;

	asm volatile("rdtsc" : "=a" (low), "=d" (high));

	return low | ((unsigned long long)high) << 32;
}

#endif
