#include <linux/record_replay.h>
#include <linux/kvm_host.h>
#include <linux/delay.h>
#include <asm/logger.h>
#include <asm/vmx.h>
#include <asm/checkpoint_rollback.h>

#include "mmu.h"

struct rr_ops *rr_ops;

/* Synchronize all vcpus before enabling record and replay.
 * Master will do things before slaves. After calling this function,
 * @nr_sync_vcpus and @nr_fin_vcpus will be set to 0.
 */
static int __rr_vcpu_sync(struct kvm_vcpu *vcpu,
			  int (*master_func)(struct kvm_vcpu *vcpu),
			  int (*slave_func)(struct kvm_vcpu *vcpu))
{
	int ret = 0;
	struct kvm *kvm = vcpu->kvm;
	struct rr_kvm_info *rr_kvm_info = &kvm->rr_info;
	int i;
	int online_vcpus = atomic_read(&kvm->online_vcpus);
	bool is_master = false;

	if (atomic_inc_return(&rr_kvm_info->nr_sync_vcpus) == 1) {
		is_master = true;
		vcpu->rr_info.is_master = true;
	} else {
		vcpu->rr_info.is_master = false;
	}

	if (is_master) {
		RR_DLOG(INIT, "vcpu=%d is the master", vcpu->vcpu_id);
		for (i = 0; i < online_vcpus; ++i) {
			if (kvm->vcpus[i] == vcpu)
				continue;
			RR_DLOG(INIT, "vcpu=%d kick vcpu=%d", vcpu->vcpu_id,
				kvm->vcpus[i]->vcpu_id);
			kvm_vcpu_kick(kvm->vcpus[i]);
		}
		RR_DLOG(INIT, "vcpu=%d wait for other vcpus to sync",
			vcpu->vcpu_id);
		/* After all the vcpus have come in, master will go first while
		 * slaves will wait until master finishes.
		 */
		while (atomic_read(&rr_kvm_info->nr_sync_vcpus) < online_vcpus) {
			msleep(1);
		}
		/* Do master things here */
		if (master_func)
			ret = master_func(vcpu);
		/* Let slaves begin */
		atomic_set(&rr_kvm_info->nr_sync_vcpus, 0);
	} else {
		RR_DLOG(INIT, "vcpu=%d is the slave", vcpu->vcpu_id);
		while (atomic_read(&rr_kvm_info->nr_sync_vcpus) != 0) {
			msleep(1);
		}
		/* Do slave things here */
		if (slave_func)
			ret = slave_func(vcpu);
	}
	atomic_inc(&rr_kvm_info->nr_fin_vcpus);
	if (is_master) {
		while (atomic_read(&rr_kvm_info->nr_fin_vcpus) < online_vcpus) {
			msleep(1);
		}
		atomic_set(&rr_kvm_info->nr_fin_vcpus, 0);
	} else {
		while (atomic_read(&rr_kvm_info->nr_fin_vcpus) != 0) {
			msleep(1);
		}
	}
	RR_DLOG(INIT, "vcpu=%d finish", vcpu->vcpu_id);
	return ret;
}

/* Initialization for RR_ASYNC_PREEMPTION_EPT */
static int __rr_ape_init(struct kvm_vcpu *vcpu)
{
	/* MUST make rr_info.enabled true before separating page tables */
	vcpu->rr_info.enabled = true;
	vcpu->rr_info.timer_value = rr_ctrl.timer_value;

	/* Obsolete existing paging structures to separate page tables of
	 * different vcpus.
	 */
	if (vcpu->rr_info.is_master) {
		vcpu->kvm->arch.mmu_valid_gen++;
	}
	kvm_mmu_unload(vcpu);
	kvm_mmu_reload(vcpu);

	rr_ops->ape_vmx_setup(vcpu->rr_info.timer_value);

	RR_DLOG(INIT, "vcpu=%d enabled, preemption_timer=%lu, root_hpa=0x%llx",
		vcpu->vcpu_id, vcpu->rr_info.timer_value,
		vcpu->arch.mmu.root_hpa);
	return 0;
}

void rr_init(struct rr_ops *vmx_rr_ops)
{
	RR_ASSERT(!rr_ops);
	rr_ops = vmx_rr_ops;
	RR_DLOG(INIT, "rr_ops initialized");
}
EXPORT_SYMBOL_GPL(rr_init);

void rr_vcpu_info_init(struct rr_vcpu_info *rr_info)
{
	memset(rr_info, 0, sizeof(*rr_info));
	rr_info->enabled = false;
	rr_info->timer_value = RR_DEFAULT_PREEMTION_TIMER_VAL;
	rr_info->requests = 0;
	rr_info->is_master = false;
	INIT_LIST_HEAD(&rr_info->events_list);
	mutex_init(&rr_info->events_list_lock);
	RR_DLOG(INIT, "rr_vcpu_info initialized");
}
EXPORT_SYMBOL_GPL(rr_vcpu_info_init);

void rr_kvm_info_init(struct rr_kvm_info *rr_kvm_info)
{
	atomic_set(&rr_kvm_info->nr_sync_vcpus, 0);
	atomic_set(&rr_kvm_info->nr_fin_vcpus, 0);
	RR_DLOG(INIT, "rr_kvm_info initialized");
}
EXPORT_SYMBOL_GPL(rr_kvm_info_init);

int rr_vcpu_enable(struct kvm_vcpu *vcpu)
{
	int ret;

	RR_DLOG(INIT, "vcpu=%d start", vcpu->vcpu_id);
	ret = __rr_vcpu_sync(vcpu, __rr_ape_init, __rr_ape_init);
	if (!ret)
		rr_make_request(RR_REQ_CHECKPOINT, &vcpu->rr_info);
	else
		RR_ERR("error: vcpu=%d fail to __rr_vcpu_sync()",
		       vcpu->vcpu_id);
	RR_DLOG(INIT, "vcpu=%d finish", vcpu->vcpu_id);
	return ret;
}
EXPORT_SYMBOL_GPL(rr_vcpu_enable);

/* Should be called within events_list_lock */
static void __rr_vcpu_clean_events(struct kvm_vcpu *vcpu)
{
	struct rr_vcpu_info *rr_info = &vcpu->rr_info;
	struct rr_event *e, *tmp;

	list_for_each_entry_safe(e, tmp, &rr_info->events_list, link) {
		RR_LOG("2 %d %d %d %d 0x%llx, %d, 0x%llx\n",
		       e->delivery_mode, e->vector, e->level,
		       e->trig_mode, vcpu->arch.regs[VCPU_REGS_RIP],
		       0, vcpu->arch.regs[VCPU_REGS_RCX]);
		list_del(&e->link);
		kfree(e);
	}
}

void rr_vcpu_checkpoint(struct kvm_vcpu *vcpu)
{
	int ret;

	mutex_lock(&vcpu->rr_info.events_list_lock);
	ret = rr_do_vcpu_checkpoint(vcpu);
	if (ret < 0) {
		RR_ERR("error: vcpu=%d fail to checkpoint", vcpu->vcpu_id);
	}
	__rr_vcpu_clean_events(vcpu);
	mutex_unlock(&vcpu->rr_info.events_list_lock);
}
EXPORT_SYMBOL_GPL(rr_vcpu_checkpoint);

void rr_vcpu_rollback(struct kvm_vcpu *vcpu)
{
	int ret;

	ret = rr_do_vcpu_rollback(vcpu);
	if (ret < 0) {
		RR_ERR("error: vcpu=%d fail to rollback", vcpu->vcpu_id);
	}
}
EXPORT_SYMBOL_GPL(rr_vcpu_rollback);
