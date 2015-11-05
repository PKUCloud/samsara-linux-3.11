#ifndef __RECORD_REPLAY_H
#define __RECORD_REPLAY_H

#include <linux/kvm.h> /* ioctl definition */
#include <linux/bitops.h>
#include <linux/mutex.h>
#include <linux/list.h>
#include <linux/kvm_types.h>

struct kvm;
struct kvm_vcpu;

#define RR_ASYNC_PREEMPTION_EPT	(KVM_RR_CTRL_MEM_EPT | KVM_RR_CTRL_MODE_ASYNC |\
				 KVM_RR_CTRL_KICK_PREEMPTION)

#define RR_DEFAULT_PREEMTION_TIMER_VAL	30000

#define RR_CHUNK_COMMIT			0
#define RR_CHUNK_ROLLBACK		1
#define RR_CHUNK_SKIP			2

#define RR_REQ_CHECKPOINT		0
#define RR_REQ_COMMIT_AGAIN		1
#define RR_REQ_POST_CHECK		2

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
};

/* Record and replay control info for kvm */
struct rr_kvm_info {
	atomic_t nr_sync_vcpus;
	atomic_t nr_fin_vcpus;
};

struct rr_ops {
	void (*ape_vmx_setup)(u32 timer_value);
	void (*tlb_flush)(struct kvm_vcpu *vcpu);
};

void rr_init(struct rr_ops *rr_ops);
void rr_vcpu_info_init(struct rr_vcpu_info *rr_info);
void rr_kvm_info_init(struct rr_kvm_info *rr_kvm_info);
int rr_vcpu_enable(struct kvm_vcpu *vcpu);
void rr_vcpu_checkpoint(struct kvm_vcpu *vcpu);
void rr_vcpu_rollback(struct kvm_vcpu *vcpu);
void rr_spte_set_pfn(u64 *sptep, pfn_t pfn);
void rr_spte_withdraw_wperm(u64 *sptep);
int rr_spte_check_pfn(u64 spte, pfn_t pfn);
void rr_commit_memory(struct kvm_vcpu *vcpu);
void rr_rollback_memory(struct kvm_vcpu *vcpu);
void rr_commit_again(struct kvm_vcpu *vcpu);

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
