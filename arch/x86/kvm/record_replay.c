#include <linux/record_replay.h>
#include <linux/kvm_host.h>
#include <linux/delay.h>
#include <asm/logger.h>
#include <asm/vmx.h>
#include <asm/checkpoint_rollback.h>

#include "mmu.h"
#include "lapic.h"

struct rr_ops *rr_ops;

/* Definitions from vmx.c */
#define __ex(x) __kvm_handle_fault_on_reboot(x)
#define __ex_clear(x, reg) \
	____kvm_handle_fault_on_reboot(x, "xor " reg " , " reg)

static __always_inline unsigned long vmcs_readl(unsigned long field)
{
	unsigned long value;

	asm volatile (__ex_clear(ASM_VMX_VMREAD_RDX_RAX, "%0")
		      : "=a"(value) : "d"(field) : "cc");
	return value;
}

static void vmcs_writel(unsigned long field, unsigned long value)
{
	u8 error;

	asm volatile (__ex(ASM_VMX_VMWRITE_RAX_RDX) "; setna %0"
		       : "=q"(error) : "a"(value), "d"(field) : "cc");
	if (unlikely(error)) {
		RR_ERR("vmwrite error: reg %lx value %lx",
		       field, value);
		dump_stack();
	}
}

static void vmcs_write32(unsigned long field, u32 value)
{
	vmcs_writel(field, value);
}

static __always_inline u64 vmcs_read64(unsigned long field)
{
#ifdef CONFIG_X86_64
	return vmcs_readl(field);
#else
	return vmcs_readl(field) | ((u64)vmcs_readl(field+1) << 32);
#endif
}

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

#define PT64_LEVEL_BITS 9

#define PT64_LEVEL_SHIFT(level) \
		(PAGE_SHIFT + (level - 1) * PT64_LEVEL_BITS)

#define PT64_NR_PT_ENTRY	512

#define SHADOW_PT_ADDR(address, index, level) \
	(address + (index << PT64_LEVEL_SHIFT(level)))

static u64 __read_mostly shadow_mmio_mask;

static inline bool is_mmio_spte(u64 spte)
{
	return (spte & shadow_mmio_mask) == shadow_mmio_mask;
}

static inline int is_shadow_present_pte(u64 pte)
{
	return pte & PT_PRESENT_MASK && !is_mmio_spte(pte);
}

static int inline is_large_pte(u64 pte)
{
	return pte & PT_PAGE_SIZE_MASK;
}

static int inline is_last_spte(u64 pte, int level)
{
	if (level == PT_PAGE_TABLE_LEVEL)
		return 1;
	if (is_large_pte(pte))
		return 1;
	return 0;
}

void rr_set_mmio_spte_mask(u64 mmio_mask)
{
	RR_DLOG(INIT, "shadow_mmio_mask set to 0x%llx", mmio_mask);
	shadow_mmio_mask = mmio_mask;
}
EXPORT_SYMBOL_GPL(rr_set_mmio_spte_mask);

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

void rr_vcpu_insert_chunk_list(struct kvm_vcpu *vcpu)
{
	struct kvm *kvm = vcpu->kvm;

	spin_lock(&kvm->chunk_list_lock);
	list_add_tail(&vcpu->chunk_info.link, &kvm->chunk_list);
	spin_unlock(&kvm->chunk_list_lock);
}
EXPORT_SYMBOL_GPL(rr_vcpu_insert_chunk_list);

void rr_vcpu_set_chunk_state(struct kvm_vcpu *vcpu, int state)
{
	struct kvm *kvm = vcpu->kvm;

	spin_lock(&kvm->chunk_list_lock);
	vcpu->chunk_info.state = state;
	spin_unlock(&kvm->chunk_list_lock);
}
EXPORT_SYMBOL_GPL(rr_vcpu_set_chunk_state);

static void rr_vcpu_chunk_list_check_and_del(struct kvm_vcpu *vcpu)
{
	struct kvm *kvm = vcpu->kvm;
	struct list_head *head = &kvm->chunk_list;
	struct chunk_info *chunk, *temp;
	bool can_leave = true;
retry:
	can_leave = true;
	spin_lock(&kvm->chunk_list_lock);
	list_for_each_entry_safe(chunk, temp, head, link) {
		if (chunk->vcpu_id == vcpu->vcpu_id) {
			/* We reach our own chunk node, which means that we
			 * can delete this node and enter guest.
			 */
			list_del(&chunk->link);
			chunk->state = RR_CHUNK_IDLE;
			break;
		}
		if (chunk->action == KVM_RR_COMMIT &&
		    chunk->state != RR_CHUNK_FINISHED) {
			/* There is one vcpu before us and it is going to
			 * commit, so we need to wait for it.
			 */
			can_leave = false;
			break;
		}
	}
	spin_unlock(&kvm->chunk_list_lock);
	if (!can_leave) {
		yield();
		goto retry;
	}
}

#ifdef RR_ROLLBACK_PAGES
static void rr_copy_rollback_pages(struct kvm_vcpu *vcpu)
{
	void *origin, *private;
	struct kvm_private_mem_page *private_page, *temp;

	list_for_each_entry_safe(private_page, temp,
				 &vcpu->arch.rollback_pages, link) {
		origin = pfn_to_kaddr(private_page->original_pfn);
		private = pfn_to_kaddr(private_page->private_pfn);
		copy_page(private, origin);
		list_move_tail(&private_page->link, &vcpu->arch.holding_pages);
		vcpu->arch.nr_rollback_pages--;
		vcpu->arch.nr_holding_pages++;
	}
}
#endif

void rr_post_check(struct kvm_vcpu *vcpu)
{
	bool is_rollback = (vcpu->chunk_info.action == KVM_RR_ROLLBACK);

	rr_vcpu_chunk_list_check_and_del(vcpu);
	rr_clear_request(RR_REQ_POST_CHECK, &vcpu->rr_info);
#ifdef RR_ROLLBACK_PAGES
	if (is_rollback)
		rr_copy_rollback_pages(vcpu);
#endif
}
EXPORT_SYMBOL_GPL(rr_post_check);

int apic_accept_irq_without_record(struct kvm_lapic *apic, int delivery_mode,
				   int vector, int level, int trig_mode,
				   unsigned long *dest_map);

int rr_apic_accept_irq(struct kvm_lapic *apic, int delivery_mode,
		       int vector, int level, int trig_mode,
		       unsigned long *dest_map)
{
	struct kvm_vcpu *vcpu = apic->vcpu;
	struct rr_event *rr_event;

	if (vcpu->rr_info.enabled) {
		mutex_lock(&(vcpu->rr_info.events_list_lock));
		rr_event = kmalloc(sizeof(struct rr_event), GFP_KERNEL);
		rr_event->delivery_mode = delivery_mode;
		rr_event->vector = vector;
		rr_event->level = level;
		rr_event->trig_mode = trig_mode;
		rr_event->dest_map = dest_map;
		list_add(&(rr_event->link), &(vcpu->rr_info.events_list));
		mutex_unlock(&(vcpu->rr_info.events_list_lock));
	}

	return apic_accept_irq_without_record(apic, delivery_mode, vector,
					      level, trig_mode, dest_map);
}
EXPORT_SYMBOL_GPL(rr_apic_accept_irq);

void rr_apic_reinsert_irq(struct kvm_vcpu *vcpu)
{
	struct rr_event *e, *tmp;

	mutex_lock(&(vcpu->rr_info.events_list_lock));
	list_for_each_entry_safe(e, tmp, &(vcpu->rr_info.events_list), link) {
		apic_accept_irq_without_record(vcpu->arch.apic,
					       e->delivery_mode,
					       e->vector, e->level,
					       e->trig_mode, e->dest_map);
	}
	mutex_unlock(&(vcpu->rr_info.events_list_lock));
}
EXPORT_SYMBOL_GPL(rr_apic_reinsert_irq);

static void  __rr_set_AD_bit(struct kvm_vcpu *vcpu, u64 *sptep, gpa_t gpa, hpa_t addr)
{
	if (*sptep & VMX_EPT_DIRTY_BIT || *sptep & VMX_EPT_ACCESS_BIT) {
		re_set_bit(gpa >> PAGE_SHIFT, &vcpu->access_bitmap);
		if (*sptep & VMX_EPT_DIRTY_BIT) {
			re_set_bit(gpa >> PAGE_SHIFT, &vcpu->dirty_bitmap);
		}
	}
	*sptep &= ~(VMX_EPT_ACCESS_BIT | VMX_EPT_DIRTY_BIT);

	/* Tamlok
	 * Move the write mask
	 * *sptep &= ~(PT_WRITABLE_MASK | SPTE_MMU_WRITEABLE);
	 * Need to mark the page clean?
	 * mmu_spte_update()?
	 * For now, we don't withdraw the write permission here. Instead, we
	 * do this when we commit or rollback private pages.
	 */
	// *sptep &= ~(PT_WRITABLE_MASK | SPTE_MMU_WRITEABLE);
}

static void __rr_walk_spt(struct kvm_vcpu *vcpu, hpa_t shadow_addr, int level,
			  gpa_t gpa)
{
	u64 index;
	gpa_t new_gpa;
	hpa_t new_addr;
	u64 *sptep;
	u64 spte;

	RR_ASSERT(level >= PT_PAGE_TABLE_LEVEL);

	for (index = 0; index < PT64_NR_PT_ENTRY; ++index) {
		sptep = ((u64 *)__va(shadow_addr)) + index;
		spte = *sptep;
		if (!is_shadow_present_pte(spte))
			continue;
		/* There is no need to walk its children if the access bit is
		 * not set.
		 */
		if (!(spte & VMX_EPT_ACCESS_BIT)) {
			continue;
		}

		new_gpa = SHADOW_PT_ADDR(gpa, index, level);
		new_addr = spte & PT64_BASE_ADDR_MASK;
		if (is_last_spte(spte, level)) {
			__rr_set_AD_bit(vcpu, sptep, new_gpa, new_addr);
		} else {
			__rr_walk_spt(vcpu, new_addr, level - 1, new_gpa);
			*sptep &= ~VMX_EPT_ACCESS_BIT;
		}
	}
}

void rr_gen_bitmap_from_spt(struct kvm_vcpu *vcpu)
{
	int level = vcpu->arch.mmu.shadow_root_level;
	hpa_t shadow_addr = vcpu->arch.mmu.root_hpa;

	RR_ASSERT(level == PT64_ROOT_LEVEL);
	RR_ASSERT((vcpu->arch.mmu.root_level == PT64_ROOT_LEVEL) &&
		  vcpu->arch.mmu.direct_map);
	__rr_walk_spt(vcpu, shadow_addr, level, 0);
}
EXPORT_SYMBOL_GPL(rr_gen_bitmap_from_spt);

static inline int rr_detect_conflict(struct region_bitmap *access_bm,
				     struct region_bitmap *conflict_bm)
{
	/* Notice the order of the arguments */
	return re_bitmap_intersects(conflict_bm, access_bm);
}

static void rr_log_chunk(struct kvm_vcpu *vcpu)
{
	struct kvm *kvm = vcpu->kvm;
	unsigned long rcx, rip;

	if (vcpu->vcpu_id == kvm->last_record_vcpu_id)
		return;
	rcx = kvm_register_read(vcpu, VCPU_REGS_RCX);
	rip = vmcs_readl(GUEST_RIP);
	kvm->last_record_vcpu_id = vcpu->vcpu_id;
	/* get_random_bytes(&bc, sizeof(unsigned int)); */
	/* The last argument should be the bc */
	RR_LOG("%d %lx %lx %x\n", vcpu->vcpu_id, rip, rcx, 0);
}

static void rr_vcpu_disable(struct kvm_vcpu *vcpu);

static int rr_ape_check_chunk(struct kvm_vcpu *vcpu)
{
	struct kvm *kvm = vcpu->kvm;
	int i;
	int online_vcpus = atomic_read(&(kvm->online_vcpus));
	int commit = 1;

	if (vcpu->rr_info.enabled) {
		rr_gen_bitmap_from_spt(vcpu);

		if (!vcpu->exclusive_commit && atomic_read(&kvm->tm_normal_commit) < 1) {
			/* Now anothter vcpu is in exclusive commit state */
			if (wait_event_interruptible(kvm->tm_exclusive_commit_que,
			    atomic_read(&kvm->tm_normal_commit) == 1)) {
				printk(KERN_ERR "error: %s wait_event_interruptible() interrupted\n",
					  __func__);
				return -1;
			}
		}

		down_read(&(kvm->tm_rwlock));
		mutex_lock(&(kvm->tm_lock));

		// Wait for DMA finished
		//tm_wait_DMA(vcpu);

		if (kvm->tm_last_commit_vcpu != vcpu->vcpu_id) {
			// Detect conflict
			if (vcpu->is_early_rb ||
			    rr_detect_conflict(&vcpu->access_bitmap,
					       vcpu->public_cb) ||
			    rr_detect_conflict(&vcpu->access_bitmap,
					       &vcpu->DMA_access_bitmap)) {
				commit = 0;
				vcpu->nr_conflict++;
				vcpu->is_early_rb = 0;
			}
		}

		if (commit) {
			if (vcpu->exclusive_commit) {
				/* Exclusive commit state */
				vcpu->exclusive_commit = 0;
				atomic_set(&kvm->tm_normal_commit, 1);
				wake_up_interruptible(&kvm->tm_exclusive_commit_que);
			} else if (atomic_read(&kvm->tm_normal_commit) < 1) {
				/* Now another vcpu is in exclusive commit state, need to rollback*/
				commit = 0;
				goto rollback;
			}
			// Set dirty bit
			for (i=0; i<online_vcpus; i++) {
				if (kvm->vcpus[i]->vcpu_id == vcpu->vcpu_id)
					continue;
				re_bitmap_or(kvm->vcpus[i]->public_cb,
					     &vcpu->dirty_bitmap);
			}

			/* Commit here in the lock */
			// tm_memory_commit(vcpu);
			// Set last commit vcpu
			kvm->tm_last_commit_vcpu = vcpu->vcpu_id;

			vcpu->nr_rollback = 0;
			rr_log_chunk(vcpu);
		} else {
rollback:
			vcpu->nr_rollback++;
			/* Rollback here in the lock */
			// tm_memory_rollback(vcpu);
			if (!vcpu->exclusive_commit && vcpu->nr_rollback >= RR_CONSEC_RB_TIME) {
				if (atomic_dec_and_test(&kvm->tm_normal_commit)) {
					/* Now we can enter exclusive commit state */
					vcpu->exclusive_commit = 1;
				}
			}
		}
		/* Get the tm_version */
		// vcpu->tm_version = atomic_inc_return(&(kvm->tm_get_version));
		/* Insert chunk_info to kvm->chunk_list */
		vcpu->chunk_info.action = commit ? KVM_RR_COMMIT : KVM_RR_ROLLBACK;
		vcpu->chunk_info.state = RR_CHUNK_BUSY;
		rr_vcpu_insert_chunk_list(vcpu);

		swap(vcpu->public_cb, vcpu->private_cb);
		mutex_unlock(&(kvm->tm_lock));

		if (commit) {
			rr_commit_memory(vcpu);
		} else rr_rollback_memory(vcpu);

		// tm_check_version(vcpu);
		rr_vcpu_set_chunk_state(vcpu, RR_CHUNK_FINISHED);

		// Clear DMA bitmap
		if (atomic_read(&(kvm->tm_dma)) == 0)
			re_bitmap_clear(&vcpu->DMA_access_bitmap);
		else
			RR_ERR("error: vcpu=%d should not come here\n",
			       vcpu->vcpu_id);
		// mutex_unlock(&(kvm->tm_lock));
		up_read(&(kvm->tm_rwlock));

	} else {
		/* Error to come here when vcpu->is_recording is false */
		printk(KERN_ERR "error: vcpu=%d %s when vcpu->is_recording is false\n",
			  vcpu->vcpu_id, __func__);
		return -1;
	}
	// Reset bitmaps
	re_bitmap_clear(&vcpu->access_bitmap);
	re_bitmap_clear(&vcpu->dirty_bitmap);
	re_bitmap_clear(vcpu->private_cb);

	if (!rr_ctrl.enabled) {
		goto record_disable;
	}

	vmcs_write32(VMX_PREEMPTION_TIMER_VALUE, rr_ctrl.timer_value);
	vcpu->nr_sync ++;
out:
	kvm_make_request(KVM_REQ_TLB_FLUSH, vcpu);
	return commit;
record_disable:
	rr_vcpu_disable(vcpu);
	goto out;
}

int rr_check_chunk(struct kvm_vcpu *vcpu)
{
	u32 exit_reason = rr_ops->get_vmx_exit_reason(vcpu);
	int ret;
	int is_early_check;

	#ifdef RR_EARLY_ROLLBACK
	if (exit_reason == EXIT_REASON_EPT_VIOLATION) {
		gfn_t gfn = vmcs_read64(GUEST_PHYSICAL_ADDRESS) >> PAGE_SHIFT;
		if (re_test_bit(gfn, vcpu->public_cb)) {
			exit_reason = EXIT_REASON_PREEMPTION_TIMER;
			vcpu->is_early_rb = 1;
		}
	}
	#endif

	#ifdef RR_EARLY_CHECK
	is_early_check = 0;
	if (exit_reason == EXIT_REASON_EPT_VIOLATION) {
		gfn_t gfn = vmcs_read64(GUEST_PHYSICAL_ADDRESS) >> PAGE_SHIFT;
		if (re_test_bit(gfn, vcpu->public_cb)) {
			exit_reason = EXIT_REASON_PREEMPTION_TIMER;
			is_early_check = 1;
		}
	}
	#endif
	if (exit_reason != EXIT_REASON_EPT_VIOLATION
	    && exit_reason != EXIT_REASON_PAUSE_INSTRUCTION) {
		ret = rr_ape_check_chunk(vcpu);
		if (ret == -1) {
			RR_ERR("error: vcpu=%d rr_ape_check_chunk() returns -1",
			       vcpu->vcpu_id);
		} else if (ret == 1) {
			rr_make_request(RR_REQ_COMMIT_AGAIN, &vcpu->rr_info);
			rr_make_request(RR_REQ_POST_CHECK, &vcpu->rr_info);
			return KVM_RR_COMMIT;
		} else {
			rr_make_request(RR_REQ_POST_CHECK, &vcpu->rr_info);
			return KVM_RR_ROLLBACK;
		}
	}

	return KVM_RR_SKIP;
}
EXPORT_SYMBOL_GPL(rr_check_chunk);

void rr_clear_holding_pages(struct kvm_vcpu *vcpu)
{
	struct kvm_private_mem_page *private_page;
	struct kvm_private_mem_page *temp;

	list_for_each_entry_safe(private_page, temp, &vcpu->arch.holding_pages,
			link) {
		rr_spte_set_pfn(private_page->sptep,
				private_page->original_pfn);
		rr_spte_withdraw_wperm(private_page->sptep);
		kfree(pfn_to_kaddr(private_page->private_pfn));
		list_del(&private_page->link);
		kfree(private_page);
		vcpu->arch.nr_holding_pages--;
	}
	INIT_LIST_HEAD(&vcpu->arch.holding_pages);
}

#ifdef RR_ROLLBACK_PAGES
void rr_clear_rollback_pages(struct kvm_vcpu *vcpu)
{
	struct kvm_private_mem_page *private_page;
	struct kvm_private_mem_page *temp;

	list_for_each_entry_safe(private_page, temp, &vcpu->arch.rollback_pages,
				 link) {
		rr_spte_set_pfn(private_page->sptep,
				private_page->original_pfn);
		rr_spte_withdraw_wperm(private_page->sptep);
		kfree(pfn_to_kaddr(private_page->private_pfn));
		list_del(&private_page->link);
		kfree(private_page);
		vcpu->arch.nr_rollback_pages--;
	}
	INIT_LIST_HEAD(&vcpu->arch.rollback_pages);
}
#endif

static void rr_vcpu_disable(struct kvm_vcpu *vcpu)
{
	struct kvm *kvm = vcpu->kvm;

	printk(KERN_ERR "XELATEX - disable kvm_record, vcpu=%d, nr_sync=%llu,"
			"nr_vmexit=%llu, nr_conflict=%llu\n",
			vcpu->vcpu_id, vcpu->nr_sync, vcpu->nr_vmexit, vcpu->nr_conflict);

	kvm->tm_last_commit_vcpu = -1;
	atomic_set(&kvm->tm_normal_commit, 1);
	atomic_set(&kvm->tm_get_version, 0);
	atomic_set(&kvm->tm_put_version, 1);
	vcpu->nr_vmexit = 0;
	vcpu->nr_sync = 0;
	vcpu->nr_conflict = 0;
	vcpu->exclusive_commit = 0;
	vcpu->nr_rollback = 0;
	vcpu->tm_version = 0;
	vcpu->rr_info.enabled = false;

	re_bitmap_destroy(&vcpu->access_bitmap);
	re_bitmap_destroy(&vcpu->conflict_bitmap_1);
	re_bitmap_destroy(&vcpu->conflict_bitmap_2);
	re_bitmap_destroy(&vcpu->dirty_bitmap);
	re_bitmap_destroy(&vcpu->DMA_access_bitmap);

	rr_clear_holding_pages(vcpu);
#ifdef RR_ROLLBACK_PAGES
	rr_clear_rollback_pages(vcpu);
#endif
	rr_ops->ape_vmx_clear();
}

