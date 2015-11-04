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

/* Definitions from mmu.c */
#define PT64_BASE_ADDR_MASK (((1ULL << 52) - 1) & ~(u64)(PAGE_SIZE-1))
#define PT_FIRST_AVAIL_BITS_SHIFT 10
#define SPTE_MMU_WRITEABLE	(1ULL << (PT_FIRST_AVAIL_BITS_SHIFT + 1))

void rr_spte_set_pfn(u64 *sptep, pfn_t pfn)
{
	u64 spte;

	spte = *sptep;
	spte &= ~PT64_BASE_ADDR_MASK;
	spte |= (u64)pfn << PAGE_SHIFT;
	*sptep = spte;
}
EXPORT_SYMBOL_GPL(rr_spte_set_pfn);

/* Withdrwo write permission of the spte */
void rr_spte_withdraw_wperm(u64 *sptep)
{
	*sptep &= ~(PT_WRITABLE_MASK | SPTE_MMU_WRITEABLE);
}
EXPORT_SYMBOL_GPL(rr_spte_withdraw_wperm);

int rr_spte_check_pfn(u64 spte, pfn_t pfn)
{
	RR_ASSERT(pfn == ((spte & PT64_BASE_ADDR_MASK) >> PAGE_SHIFT));
	return 0;
}
EXPORT_SYMBOL_GPL(rr_spte_check_pfn);

#ifndef RR_HOLDING_PAGES
/* Commit the private pages to the original ones. Called when a quantum is
 * finished and can commit.
 */
void rr_commit_memory(struct kvm_vcpu *vcpu)
{
	struct kvm_private_mem_page *private_page;
	struct kvm_private_mem_page *temp;
	void *origin, *private;
	u64 old_spte;

	list_for_each_entry_safe(private_page, temp, &vcpu->arch.private_pages,
		link)
	{
		origin = pfn_to_kaddr(private_page->original_pfn);
		private = pfn_to_kaddr(private_page->private_pfn);
		copy_page(origin, private);
		old_spte = *(private_page->sptep);

		rr_spte_check_pfn(*(private_page->sptep),
				  private_page->private_pfn);
		rr_spte_set_pfn(private_page->sptep,
				private_page->original_pfn);
		/* Widthdraw the write permission */
		rr_spte_withdraw_wperm(private_page->sptep);
		kfree(private);
		list_del(&private_page->link);
		kfree(private_page);
		vcpu->arch.nr_private_pages--;
	}
	INIT_LIST_HEAD(&vcpu->arch.private_pages);
}
#else
/* Commit one private page */
static inline void __commit_memory_page(struct kvm_private_mem_page *private_page)
{
	void *origin, *private;

	origin = pfn_to_kaddr(private_page->original_pfn);
	private = pfn_to_kaddr(private_page->private_pfn);
	copy_page(origin, private);
}

/* Commit memory.
 * 1. Check the holding_pages list. For each node, test the gfn in
 *    conflict_bitmap. If set, this page was updated by other vcpus and we need
 *    to release the private pages and this node, set back the original pfn in
 *    spte, withdraw the write permission. If not, test the gfn in dirty_bitmap.
 *    If set, this page was written by this vcpu in this quantum. We need to
 *    update the content back to the original page.
 * 2. Commit the private_pages list and move it to the back of the
 *    holding_pages list.
 */
void rr_commit_memory(struct kvm_vcpu *vcpu)
{
	struct kvm_private_mem_page *private_page;
	struct kvm_private_mem_page *temp;
	gfn_t gfn;
	struct list_head temp_list;
	void *origin, *private;
	u64 old_spte;

	INIT_LIST_HEAD(&temp_list); /* Hold pages temporary */
	/* Traverse the holding_pages */
	list_for_each_entry_safe(private_page, temp, &vcpu->arch.holding_pages,
				 link) {
		gfn = private_page->gfn;
		/* Whether this page has been touched by other vcpus */
		if (re_test_bit(gfn, vcpu->private_cb)) {
			rr_spte_set_pfn(private_page->sptep,
					private_page->original_pfn);
			rr_spte_withdraw_wperm(private_page->sptep);
			kfree(pfn_to_kaddr(private_page->private_pfn));
			list_del(&private_page->link);
			kfree(private_page);
			vcpu->arch.nr_holding_pages--;
		} else if (re_test_bit(gfn, &vcpu->dirty_bitmap)) {
			/* This page was touched by this vcpu in this quantum */
			__commit_memory_page(private_page);
			list_move_tail(&private_page->link, &temp_list);
		}
	}

	if (!list_empty(&temp_list)) {
		/* Move the temp_list to the back of the holding_pages */
		list_splice_tail_init(&temp_list, &vcpu->arch.holding_pages);
	}

	/* May be useless */
	//if (vcpu->arch.nr_holding_pages == 0) {
	//	INIT_LIST_HEAD(&vcpu->arch.holding_pages);
	//}

	/* Traverse the private_pages */
	list_for_each_entry_safe(private_page, temp, &vcpu->arch.private_pages,
				 link) {
		if (memslot_id(vcpu->kvm, private_page->gfn) == 8) {
			__commit_memory_page(private_page);
			list_move_tail(&private_page->link, &vcpu->arch.holding_pages);
			vcpu->arch.nr_private_pages--;
			vcpu->arch.nr_holding_pages++;
		} else {
			origin = pfn_to_kaddr(private_page->original_pfn);
			private = pfn_to_kaddr(private_page->private_pfn);
			copy_page(origin, private);
			old_spte = *(private_page->sptep);

			rr_spte_check_pfn(*(private_page->sptep),
					  private_page->private_pfn);
			rr_spte_set_pfn(private_page->sptep,
					private_page->original_pfn);
			/* Widthdraw the write permission */
			rr_spte_withdraw_wperm(private_page->sptep);
			kfree(private);
			list_del(&private_page->link);
			kfree(private_page);
			vcpu->arch.nr_private_pages--;
		}
	}
	INIT_LIST_HEAD(&vcpu->arch.private_pages);

	if (vcpu->arch.nr_holding_pages > RR_HOLDING_PAGES_MAXM) {
		// Delete old holding_pages
		list_for_each_entry_safe(private_page, temp,
					 &vcpu->arch.holding_pages, link) {
			rr_spte_set_pfn(private_page->sptep,
					private_page->original_pfn);
			rr_spte_withdraw_wperm(private_page->sptep);
			kfree(pfn_to_kaddr(private_page->private_pfn));
			list_del(&private_page->link);
			kfree(private_page);
			vcpu->arch.nr_holding_pages--;
			if (vcpu->arch.nr_holding_pages <=
			    RR_HOLDING_PAGES_TARGET_NR) {
				break;
			}
		}
	}

	// Copy inconsistent page based on DMA access bitmap
	if (vcpu->need_dma_check) {
		list_for_each_entry_safe(private_page, temp,
					 &vcpu->arch.holding_pages,
					 link) {
			gfn = private_page->gfn;
			origin = pfn_to_kaddr(private_page->original_pfn);
			private = pfn_to_kaddr(private_page->private_pfn);
			if (re_test_bit(gfn, &vcpu->DMA_access_bitmap)) {
				copy_page(private, origin);
			}
		}
		vcpu->need_dma_check = 0;
	}
/*
	// TEST: Copy inconsistent pages
	list_for_each_entry_safe(private_page, temp, &vcpu->arch.holding_pages,
				 link) {
		int i;
		gfn = private_page->gfn;
		origin = pfn_to_kaddr(private_page->original_pfn);
		private = pfn_to_kaddr(private_page->private_pfn);
		for (i=0; i<PAGE_SIZE; i++) {
			if (((char*)origin)[i] != ((char*)private)[i]) {
				copy_page(private, origin);
			}
		}
	}
*/
}
#endif
EXPORT_SYMBOL_GPL(rr_commit_memory);

#ifndef RR_HOLDING_PAGES
/* Rollback the private pages to the original ones. Called when a quantum is
 * finished and conflict with others so that have to rollback.
 */
void rr_rollback_memory(struct kvm_vcpu *vcpu)
{
	struct kvm_private_mem_page *private_page;
	struct kvm_private_mem_page *temp;
	u64 old_spte;

	list_for_each_entry_safe(private_page, temp, &vcpu->arch.private_pages,
		link)
	{
		old_spte = *(private_page->sptep);
		rr_spte_check_pfn(*(private_page->sptep),
				  private_page->private_pfn);
		rr_spte_set_pfn(private_page->sptep,
				private_page->original_pfn);
		/* Widthdraw the write permission */
		rr_spte_withdraw_wperm(private_page->sptep);

		kfree(pfn_to_kaddr(private_page->private_pfn));
		list_del(&private_page->link);
		kfree(private_page);
		vcpu->arch.nr_private_pages--;
	}
	INIT_LIST_HEAD(&vcpu->arch.private_pages);
}
#else
/* Rollback memory.
 * 1. Check the holding_pages list. For each node, test the gfn in
 *    conflict_bitmap. If set, this page was updated by other vcpus and we need
 *    to release the private pages and this node, set back the original pfn in
 *    spte, withdraw the write permission. If not, test the gfn in dirty_bitmap.
 *    If set, this page was written by this vcpu in this quantum. We need to
 *    rollback this page.
 * 2. Rollback the private_pages list.
 */
void rr_rollback_memory(struct kvm_vcpu *vcpu)
{
	struct kvm_private_mem_page *private_page;
	struct kvm_private_mem_page *temp;
	gfn_t gfn;
	void *origin, *private;

	/* Traverse the holding_pages */
	list_for_each_entry_safe(private_page, temp, &vcpu->arch.holding_pages,
				 link) {
		gfn = private_page->gfn;
#ifdef RR_ROLLBACK_PAGES
		if (re_test_bit(gfn, &vcpu->dirty_bitmap)) {
			/* We do nothing here but keep these dirty pages in a
			 * list and copy the new content back before entering
			 * guest.
			 */
			list_move_tail(&private_page->link,
				       &vcpu->arch.rollback_pages);
			vcpu->arch.nr_holding_pages--;
			vcpu->arch.nr_rollback_pages++;
		} else if (re_test_bit(gfn, vcpu->private_cb)) {
			rr_spte_set_pfn(private_page->sptep,
					private_page->original_pfn);
			rr_spte_withdraw_wperm(private_page->sptep);
			kfree(pfn_to_kaddr(private_page->private_pfn));
			list_del(&private_page->link);
			kfree(private_page);
			vcpu->arch.nr_holding_pages--;
		}
#else
		/* Whether this page has been touched by other vcpus or by this vcpu
		 * in this quantum.
		 */
		if (re_test_bit(gfn, vcpu->private_cb) ||
		    re_test_bit(gfn, &vcpu->dirty_bitmap)) {
			rr_spte_set_pfn(private_page->sptep,
					private_page->original_pfn);
			rr_spte_withdraw_wperm(private_page->sptep);
			kfree(pfn_to_kaddr(private_page->private_pfn));
			list_del(&private_page->link);
			kfree(private_page);
			vcpu->arch.nr_holding_pages--;
		}
#endif
	}
	if (vcpu->arch.nr_holding_pages == 0) {
		INIT_LIST_HEAD(&vcpu->arch.holding_pages);
	}

	/* Traverse the private_pages */
	list_for_each_entry_safe(private_page, temp, &vcpu->arch.private_pages,
				 link)
	{
#ifdef RR_ROLLBACK_PAGES
		/* We do nothing here but keep these dirty pages in a
		 * list and copy the new content back before entering
		 * guest.
		 */
		list_move_tail(&private_page->link,
			       &vcpu->arch.rollback_pages);
		vcpu->arch.nr_private_pages--;
		vcpu->arch.nr_rollback_pages++;
		continue;
#endif
		rr_spte_set_pfn(private_page->sptep,
				private_page->original_pfn);
		rr_spte_withdraw_wperm(private_page->sptep);
		kfree(pfn_to_kaddr(private_page->private_pfn));
		list_del(&private_page->link);
		kfree(private_page);
		vcpu->arch.nr_private_pages--;
	}
	INIT_LIST_HEAD(&vcpu->arch.private_pages);

	// Copy inconsistent page based on DMA access bitmap
	if (vcpu->need_dma_check) {
		list_for_each_entry_safe(private_page, temp, &vcpu->arch.holding_pages,
					 link) {
			gfn = private_page->gfn;
			origin = pfn_to_kaddr(private_page->original_pfn);
			private = pfn_to_kaddr(private_page->private_pfn);
			if (re_test_bit(gfn, &vcpu->DMA_access_bitmap)) {
				copy_page(private, origin);
			}
		}
		vcpu->need_dma_check = 0;
	}
}
#endif
EXPORT_SYMBOL_GPL(rr_rollback_memory);

/* Assume that pages committed here will never conflit with other vcpus. */
void rr_commit_again(struct kvm_vcpu *vcpu)
{
	struct kvm *kvm = vcpu->kvm;
	int i;
	int online_vcpus = atomic_read(&kvm->online_vcpus);
	struct gfn_list *gfn_node, *temp;
	bool is_clean = list_empty(&vcpu->commit_again_gfn_list);

	/* Get access_bitmap and dirty_bitmap. Clean AD bits. */
	//tm_walk_mmu(vcpu, PT_PAGE_TABLE_LEVEL);

	// Fill in dirty_bitmap
	list_for_each_entry_safe(gfn_node, temp, &(vcpu->commit_again_gfn_list), link) {
		re_set_bit(gfn_node->gfn, &vcpu->dirty_bitmap);
		list_del(&gfn_node->link);
	}

	// Wait for DMA finished
	//tm_wait_DMA(vcpu);

	down_read(&kvm->tm_rwlock);

	/* See if we really has something to commit again */
	if (is_clean && !vcpu->need_dma_check) {
		up_read(&kvm->tm_rwlock);
		return;
	}

	mutex_lock(&kvm->tm_lock);
	/* Spread the dirty_bitmap to other vcpus's conflict_bitmap */
	for (i = 0; i < online_vcpus; ++i) {
		if (kvm->vcpus[i]->vcpu_id == vcpu->vcpu_id)
			continue;
		re_bitmap_or(kvm->vcpus[i]->public_cb, &vcpu->dirty_bitmap);
	}
	/* Copy conflict_bitmap */
	// bitmap_copy(vcpu->private_conflict_bitmap, vcpu->conflict_bitmap,
	//	    TM_BITMAP_SIZE);
	swap(vcpu->private_cb, vcpu->public_cb);

	/* Commit memory here */
	rr_commit_memory(vcpu);

	//bitmap_clear(vcpu->conflict_bitmap, 0, TM_BITMAP_SIZE);
	mutex_unlock(&kvm->tm_lock);

	re_bitmap_clear(&vcpu->DMA_access_bitmap);

	up_read(&kvm->tm_rwlock);

	/* Reset bitmaps */
	re_bitmap_clear(&vcpu->access_bitmap);
	re_bitmap_clear(&vcpu->dirty_bitmap);
	re_bitmap_clear(vcpu->private_cb);

	/* Should flush right now instead of making request */
	rr_ops->tlb_flush(vcpu);
	return;
}
EXPORT_SYMBOL_GPL(rr_commit_again);

