#include <linux/record_replay.h>
#include <linux/kvm_host.h>
#include <linux/delay.h>
#include <asm/logger.h>
#include <asm/vmx.h>
#include <asm/checkpoint_rollback.h>

#include "mmu.h"
#include "lapic.h"

struct rr_ops *rr_ops;
/* Cache for struct rr_cow_page */
struct kmem_cache *rr_cow_page_cache;
/* Cache for a private page of memory */
struct kmem_cache *rr_priv_page_cache;
/* Cache for struct rr_event */
struct kmem_cache *rr_event_cache;
/* Cache for struct gfn_list */
struct kmem_cache *rr_gfn_list_cache;

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

static __always_inline void vmcs_writel(unsigned long field,
					unsigned long value)
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

static __always_inline void vmcs_write32(unsigned long field, u32 value)
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
 * Master will do master_pre_func before slaves. And do master_post_func
 * after slaves. After calling this function,
 * @nr_sync_vcpus and @nr_fin_vcpus will be set to 0.
 */
static int __rr_vcpu_sync(struct kvm_vcpu *vcpu,
			  int (*master_pre_func)(struct kvm_vcpu *vcpu),
			  int (*slave_func)(struct kvm_vcpu *vcpu),
			  int (*master_post_func)(struct kvm_vcpu *vcpu))
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
			kvm_make_request(KVM_REQ_EVENT, kvm->vcpus[i]);
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
		if (master_pre_func)
			ret = master_pre_func(vcpu);
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
		if (master_post_func)
			ret = master_post_func(vcpu);
		atomic_set(&rr_kvm_info->nr_fin_vcpus, 0);
	} else {
		while (atomic_read(&rr_kvm_info->nr_fin_vcpus) != 0) {
			msleep(1);
		}
	}
	RR_DLOG(INIT, "vcpu=%d finish", vcpu->vcpu_id);
	return ret;
}

struct gfn_list {
	struct list_head link;
	gfn_t gfn;
};

static void __rr_kvm_enable(struct kvm *kvm);
static void __rr_vcpu_enable(struct kvm_vcpu *vcpu);

static void __rr_kmem_cache_init(void)
{
	/* Init kmem_cache */
	if (!rr_cow_page_cache) {
		rr_cow_page_cache = kmem_cache_create("rr_cow_page",
						      sizeof(struct rr_cow_page),
						      0, 0, NULL);
		if (!rr_cow_page_cache) {
			RR_ERR("error: fail to kmem_cache_create() for "
			       "rr_cow_page");
			goto out;
		}
	}

	if (!rr_priv_page_cache) {
		rr_priv_page_cache = kmem_cache_create("rr_priv_page",
						       PAGE_SIZE, 0, 0, NULL);
		if (!rr_priv_page_cache) {
			RR_ERR("error: fail to kmem_cache_create() for "
			       "rr_priv_page");
			goto free_cow;
		}
	}

	if (!rr_event_cache) {
		rr_event_cache = kmem_cache_create("rr_event",
						   sizeof(struct rr_event),
						   0, 0, NULL);
		if (!rr_event_cache) {
			RR_ERR("error: fail to kmem_cache_create() for "
			       "rr_event");
			goto free_priv;
		}
	}

	if (!rr_gfn_list_cache) {
		rr_gfn_list_cache = kmem_cache_create("rr_gfn_list",
						      sizeof(struct gfn_list),
						      0, 0, NULL);
		if (unlikely(!rr_gfn_list_cache)) {
			RR_ERR("error: fail to kmem_cache_create() for "
			       "gfn_list");
			goto free_event;
		}
	}

	RR_DLOG(INIT, "kmem_cache initialized");
out:
	return;

free_event:
	kmem_cache_destroy(rr_event_cache);
	rr_event_cache = NULL;

free_priv:
	kmem_cache_destroy(rr_priv_page_cache);
	rr_priv_page_cache = NULL;

free_cow:
	kmem_cache_destroy(rr_cow_page_cache);
	rr_cow_page_cache = NULL;
}

/* Initialization for RR_ASYNC_PREEMPTION_EPT */
static int __rr_ape_init(struct kvm_vcpu *vcpu)
{
	if (vcpu->rr_info.is_master) {
		__rr_kmem_cache_init();
	}

	/* MUST make rr_info.enabled true before separating page tables */
	__rr_vcpu_enable(vcpu);

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

static int __rr_ape_post_init(struct kvm_vcpu *vcpu)
{
	RR_DLOG(INIT, "vcpu=%d", vcpu->vcpu_id);
	RR_ASSERT(vcpu->rr_info.is_master);
	__rr_kvm_enable(vcpu->kvm);
	return 0;
}

void rr_init(struct rr_ops *vmx_rr_ops)
{
	RR_ASSERT(!rr_ops);
	rr_ops = vmx_rr_ops;
	RR_DLOG(INIT, "rr_ops initialized");
}
EXPORT_SYMBOL_GPL(rr_init);

/* Called when creating vcpu */
void rr_vcpu_info_init(struct kvm_vcpu *vcpu)
{
	struct rr_vcpu_info *rr_info = &vcpu->rr_info;

	memset(rr_info, 0, sizeof(*rr_info));
	rr_info->enabled = false;
	rr_info->is_master = false;
	rr_info->requests = 0;
	rr_info->tlb_flush = true;

	RR_DLOG(INIT, "vcpu=%d rr_vcpu_info initialized partially",
		vcpu->vcpu_id);
}
EXPORT_SYMBOL_GPL(rr_vcpu_info_init);

static void __rr_vcpu_enable(struct kvm_vcpu *vcpu)
{
	struct rr_vcpu_info *rr_info = &vcpu->rr_info;

	if (rr_ctrl.timer_value != 0) {
		rr_info->timer_value = rr_ctrl.timer_value;
	} else {
		rr_info->timer_value = RR_DEFAULT_PREEMTION_TIMER_VAL;
	}

	rr_info->requests = 0;
	INIT_LIST_HEAD(&rr_info->events_list);
	mutex_init(&rr_info->events_list_lock);
	INIT_LIST_HEAD(&rr_info->commit_again_gfn_list);
	re_bitmap_init(&rr_info->access_bitmap, true);
	re_bitmap_init(&rr_info->dirty_bitmap, true);
	re_bitmap_init(&rr_info->conflict_bitmap_1, false);
	re_bitmap_init(&rr_info->conflict_bitmap_2, false);
	rr_info->public_cb = &rr_info->conflict_bitmap_1;
	rr_info->private_cb = &rr_info->conflict_bitmap_2;
	rr_info->exclusive_commit = 0;
	rr_info->nr_rollback = 0;
	rr_info->chunk_info.vcpu_id = vcpu->vcpu_id;
	rr_info->chunk_info.state = RR_CHUNK_STATE_IDLE;
	INIT_LIST_HEAD(&rr_info->private_pages);
	rr_info->nr_private_pages = 0;
	INIT_LIST_HEAD(&rr_info->holding_pages);
	rr_info->nr_holding_pages = 0;
#ifdef RR_ROLLBACK_PAGES
	INIT_LIST_HEAD(&rr_info->rollback_pages);
	rr_info->nr_rollback_pages = 0;
#endif
	rr_info->tlb_flush = true;
	rr_info->enabled = true;
	RR_DLOG(INIT, "vcpu=%d rr_vcpu_info initialized", vcpu->vcpu_id);
}

/* Called when creating a vm */
void rr_kvm_info_init(struct kvm *kvm)
{
	struct rr_kvm_info *rr_kvm_info = &kvm->rr_info;

	memset(rr_kvm_info, 0, sizeof(*rr_kvm_info));
	rr_kvm_info->enabled = false;
	atomic_set(&rr_kvm_info->nr_sync_vcpus, 0);
	atomic_set(&rr_kvm_info->nr_fin_vcpus, 0);
	rr_kvm_info->dma_holding_sem = false;

	RR_DLOG(INIT, "rr_kvm_info initialized partially");
}
EXPORT_SYMBOL_GPL(rr_kvm_info_init);

static void __rr_kvm_enable(struct kvm *kvm)
{
	struct rr_kvm_info *rr_kvm_info = &kvm->rr_info;

	mutex_init(&rr_kvm_info->tm_lock);
	spin_lock_init(&rr_kvm_info->chunk_list_lock);
	INIT_LIST_HEAD(&rr_kvm_info->chunk_list);
	rr_kvm_info->last_commit_vcpu = -1;
	atomic_set(&rr_kvm_info->normal_commit, 1);
	rr_kvm_info->last_record_vcpu = -1;
	rr_kvm_info->dma_holding_sem = false;
	init_rwsem(&rr_kvm_info->tm_rwlock);
	init_waitqueue_head(&rr_kvm_info->exclu_commit_que);
	rr_kvm_info->enabled = true;

	RR_DLOG(INIT, "rr_kvm_info initialized");
}

int rr_vcpu_enable(struct kvm_vcpu *vcpu)
{
	int ret;

	RR_DLOG(INIT, "vcpu=%d start", vcpu->vcpu_id);
	ret = __rr_vcpu_sync(vcpu, __rr_ape_init, __rr_ape_init,
			     __rr_ape_post_init);
	if (!ret)
		rr_make_request(RR_REQ_CHECKPOINT, &vcpu->rr_info);
	else
		RR_ERR("error: vcpu=%d fail to __rr_vcpu_sync()",
		       vcpu->vcpu_id);
	RR_DLOG(INIT, "vcpu=%d finish", vcpu->vcpu_id);
	printk(KERN_INFO "vcpu=%d enabled\n", vcpu->vcpu_id);
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
		kmem_cache_free(rr_event_cache, e);
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

#define PT64_INDEX(address, level)\
	(((address) >> PT64_LEVEL_SHIFT(level)) & ((1 << PT64_LEVEL_BITS) - 1))

#define SHADOW_PT_INDEX(addr, level) PT64_INDEX(addr, level)

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

static inline void rr_spte_set_cow_tag(u64 *sptep)
{
	RR_ASSERT(!(*sptep & RR_PT_COW_TAG));
	*sptep |= RR_PT_COW_TAG;
}

static inline void rr_spte_clear_cow_tag(u64 *sptep)
{
	*sptep &= ~RR_PT_COW_TAG;
}

static inline void rr_spte_set_pfn(u64 *sptep, pfn_t pfn)
{
	u64 spte;

	spte = *sptep;
	spte &= ~PT64_BASE_ADDR_MASK;
	spte |= (u64)pfn << PAGE_SHIFT;
	*sptep = spte;
}

/* Withdrwo write permission of the spte */
static inline void rr_spte_withdraw_wperm(u64 *sptep)
{
	*sptep &= ~PT_WRITABLE_MASK;
}

static inline bool rr_spte_check_pfn(u64 spte, pfn_t pfn)
{
	return (pfn == ((spte & PT64_BASE_ADDR_MASK) >> PAGE_SHIFT));
}

/* Separate memory with copy-on-write
 * Alloc a new page to replace the original page and update the spte, then add
 * an item to vcpu->arch.private_pages list.
 */
void rr_memory_cow(struct kvm_vcpu *vcpu, u64 *sptep, pfn_t pfn, gfn_t gfn)
{
	void *new_page;
	struct rr_cow_page *private_mem_page;

	/* Use GFP_ATOMIC here as it will be called while holding spinlock */
	private_mem_page = kmem_cache_alloc(rr_cow_page_cache, GFP_ATOMIC);
	if (unlikely(!private_mem_page)) {
		RR_ERR("error: vcpu=%d failed to kmem_cache_alloc() for "
		       "private_mem_page", vcpu->vcpu_id);
		return;
	}

	new_page = kmem_cache_alloc(rr_priv_page_cache, GFP_ATOMIC);
	if (unlikely(!new_page)) {
		RR_ERR("error: vcpu=%d failed to kmem_cache_alloc() for "
		       "new_page", vcpu->vcpu_id);
		kmem_cache_free(rr_cow_page_cache, private_mem_page);
		return;
	}
	private_mem_page->gfn = gfn;
	private_mem_page->original_pfn = pfn;
	private_mem_page->original_addr = pfn_to_kaddr(pfn);
	private_mem_page->private_pfn = __pa(new_page) >> PAGE_SHIFT;
	private_mem_page->private_addr = new_page;
	private_mem_page->sptep = sptep;
	copy_page(new_page, private_mem_page->original_addr);
	rr_spte_set_pfn(sptep, private_mem_page->private_pfn);
	rr_spte_set_cow_tag(sptep);

	/* Add it to the list */
	list_add(&private_mem_page->link, &vcpu->rr_info.private_pages);
	vcpu->rr_info.nr_private_pages++;
}
EXPORT_SYMBOL_GPL(rr_memory_cow);

/* Just cow but not change the sptep yet */
void rr_memory_cow_fast(struct kvm_vcpu *vcpu, u64 *sptep, gfn_t gfn)
{
	void *new_page;
	struct rr_cow_page *private_mem_page;
	pfn_t pfn = (*sptep & PT64_BASE_ADDR_MASK) >> PAGE_SHIFT;
	struct rr_vcpu_info *vrr_info = &vcpu->rr_info;

	private_mem_page = kmem_cache_alloc(rr_cow_page_cache, GFP_ATOMIC);
	if (unlikely(!private_mem_page)) {
		RR_ERR("error: vcpu=%d failed to kmem_cache_alloc() for "
		       "private_mem_page", vcpu->vcpu_id);
		return;
	}

	new_page = kmem_cache_alloc(rr_priv_page_cache, GFP_ATOMIC);
	if (unlikely(!new_page)) {
		RR_ERR("error: vcpu=%d failed to kmem_cache_alloc() for "
		       "new_page", vcpu->vcpu_id);
		kmem_cache_free(rr_cow_page_cache, private_mem_page);
		return;
	}
	private_mem_page->gfn = gfn;
	private_mem_page->original_pfn = pfn;
	private_mem_page->original_addr = pfn_to_kaddr(pfn);
	private_mem_page->private_pfn = __pa(new_page) >> PAGE_SHIFT;
	private_mem_page->private_addr = new_page;
	private_mem_page->sptep = sptep;
	copy_page(new_page, private_mem_page->original_addr);
	rr_spte_set_pfn(sptep, private_mem_page->private_pfn);
	rr_spte_set_cow_tag(sptep);
	*sptep |= PT_WRITABLE_MASK;

	/* Add it to the list */
	list_add(&private_mem_page->link, &vrr_info->private_pages);
	vrr_info->nr_private_pages++;

	return;
}
EXPORT_SYMBOL_GPL(rr_memory_cow_fast);

static int rr_clear_AD_bit_by_gfn(struct kvm_vcpu *vcpu, gfn_t gfn)
{
	int level = vcpu->arch.mmu.shadow_root_level;
	hpa_t addr = (u64)gfn << PAGE_SHIFT;
	hpa_t shadow_addr = vcpu->arch.mmu.root_hpa;
	unsigned index;
	u64 *sptep;

	RR_ASSERT(level == PT64_ROOT_LEVEL);
	RR_ASSERT(shadow_addr != INVALID_PAGE);

	for (; level >= PT_PAGE_TABLE_LEVEL; --level) {
		index = SHADOW_PT_INDEX(addr, level);
		sptep = ((u64 *)__va(shadow_addr)) + index;
		if (unlikely(!is_shadow_present_pte(*sptep))) {
			return -1;
		}
		*sptep &= ~(VMX_EPT_ACCESS_BIT);
		if (is_last_spte(*sptep, level)) {
			*sptep &= ~(VMX_EPT_DIRTY_BIT);
			return 0;
		}
		shadow_addr = *sptep & PT64_BASE_ADDR_MASK;
	}
	return 0;
}

static void *__rr_ept_gfn_to_kaddr(struct kvm_vcpu *vcpu, gfn_t gfn, int write,
				   u64 *present)
{
	int level = vcpu->arch.mmu.shadow_root_level;
	hpa_t addr = (u64)gfn << PAGE_SHIFT;
	hpa_t shadow_addr = vcpu->arch.mmu.root_hpa;
	unsigned index;
	u64 *sptep;
	u64 spte;
	u64 bitand = PT_PRESENT_MASK;

	RR_ASSERT(level == PT64_ROOT_LEVEL);
	RR_ASSERT(shadow_addr != INVALID_PAGE);

	for (; level >= PT_PAGE_TABLE_LEVEL; level --) {
		index = SHADOW_PT_INDEX(addr, level);
		sptep = ((u64 *)__va(shadow_addr)) + index;
		spte = *sptep;
		bitand &= spte;
		if (!is_shadow_present_pte(spte)) {
			*present = bitand;
			return NULL;
		}
		*sptep |= VMX_EPT_ACCESS_BIT;
		if (is_last_spte(spte, level)) {
			*present = bitand;
			if (write) {
				if (!(spte & PT_WRITABLE_MASK)) {
					return NULL;
				}
				*sptep |= VMX_EPT_DIRTY_BIT;
			}
			return (u64 *)__va(spte & PT64_BASE_ADDR_MASK);
		}
		shadow_addr = spte & PT64_BASE_ADDR_MASK;
	}
	*present = bitand;
	return NULL;
}

int tdp_page_fault(struct kvm_vcpu *vcpu, gva_t gpa, u32 error_code,
		   bool prefault);

void *rr_ept_gfn_to_kaddr(struct kvm_vcpu *vcpu, gfn_t gfn, int write)
{
	void *kaddr;
	int r;
	u32 error_code = 0;
	u32 temp;
	struct rr_vcpu_info *vrr_info = &vcpu->rr_info;
	gpa_t gpa;
	u64 present;

	kaddr = __rr_ept_gfn_to_kaddr(vcpu, gfn, write, &present);
	if (kaddr == NULL) {
		if (write)
			error_code |= PFERR_WRITE_MASK;
		gpa = gfn_to_gpa(gfn);
		while (kaddr == NULL) {
			if (present) {
				temp = error_code | PFERR_PRESENT_MASK;
			} else temp = error_code;

			r = tdp_page_fault(vcpu, gpa, temp, false);
			if (unlikely(r < 0)) {
				RR_ERR("error: vcpu=%d tdp_page_fault failed "
				       "for gfn=0x%llx r=%d",
				       vcpu->vcpu_id, gfn, r);
				return NULL;
			}
			kaddr = __rr_ept_gfn_to_kaddr(vcpu, gfn, write,
						      &present);
		}
	}

	vrr_info->tlb_flush = true;
	/* Generate commit again gfn list */
	if (rr_check_request(RR_REQ_COMMIT_AGAIN, vrr_info)) {
		if (write) {
			struct gfn_list *gfn_node = kmem_cache_alloc(rr_gfn_list_cache,
								     GFP_ATOMIC);
			if (unlikely(!gfn_node)) {
				RR_ERR("error: vcpu=%d failed to "
				       "kmem_cache_alloc() for gfn_list",
				       vcpu->vcpu_id);
				goto out;
			}
			gfn_node->gfn = gfn;
			list_add(&gfn_node->link,
				 &(vrr_info->commit_again_gfn_list));
		}
		rr_clear_AD_bit_by_gfn(vcpu, gfn);
	}
out:
	return kaddr;
}
EXPORT_SYMBOL_GPL(rr_ept_gfn_to_kaddr);

#ifndef RR_HOLDING_PAGES
/* Commit the private pages to the original ones. Called when a quantum is
 * finished and can commit.
 */
static void rr_commit_memory(struct kvm_vcpu *vcpu)
{
	struct rr_cow_page *private_page;
	struct rr_cow_page *temp;
	struct rr_vcpu_info *vrr_info = &vcpu->rr_info;

	list_for_each_entry_safe(private_page, temp,
				 &vrr_info->private_pages,
				 link)
	{
		copy_page(private_page->original_addr,
			  private_page->private_addr);
		RR_ASSERT(rr_spte_check_pfn(*(private_page->sptep),
					    private_page->private_pfn));
		rr_spte_set_pfn(private_page->sptep,
				private_page->original_pfn);
		/* Widthdraw the write permission */
		rr_spte_withdraw_wperm(private_page->sptep);
		rr_spte_clear_cow_tag(private_page->sptep);
		kmem_cache_free(rr_priv_page_cache,
				private_page->private_addr);
		list_del(&private_page->link);
		kmem_cache_free(rr_cow_page_cache, private_page);
		vrr_info->nr_private_pages--;
	}
}
#else
static inline void rr_age_holding_page(struct rr_vcpu_info *vrr_info,
				       struct rr_cow_page *private_page)
{
	if ((++(private_page->age)) >= RR_MAX_HOLDING_PAGE_AGE) {
		rr_spte_set_pfn(private_page->sptep,
				private_page->original_pfn);
		rr_spte_withdraw_wperm(private_page->sptep);
		rr_spte_clear_cow_tag(private_page->sptep);
		kmem_cache_free(rr_priv_page_cache,
				private_page->private_addr);
		list_del(&private_page->link);
		kmem_cache_free(rr_cow_page_cache, private_page);
		vrr_info->nr_holding_pages--;
	}
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
static void rr_commit_memory(struct kvm_vcpu *vcpu)
{
	struct rr_cow_page *private_page;
	struct rr_cow_page *temp;
	gfn_t gfn;
	struct list_head temp_list;
	struct rr_vcpu_info *vrr_info = &vcpu->rr_info;
	struct kvm *kvm = vcpu->kvm;

	INIT_LIST_HEAD(&temp_list); /* Hold pages temporary */
	/* Traverse the holding_pages */
	list_for_each_entry_safe(private_page, temp,
				 &vrr_info->holding_pages, link) {
		gfn = private_page->gfn;
		/* Whether this page has been touched by other vcpus */
		if (re_test_bit(gfn, vrr_info->private_cb)) {
			rr_spte_set_pfn(private_page->sptep,
					private_page->original_pfn);
			rr_spte_withdraw_wperm(private_page->sptep);
			rr_spte_clear_cow_tag(private_page->sptep);
			kmem_cache_free(rr_priv_page_cache,
					private_page->private_addr);
			list_del(&private_page->link);
			kmem_cache_free(rr_cow_page_cache, private_page);
			vrr_info->nr_holding_pages--;
		} else if (re_test_bit(gfn, &vrr_info->dirty_bitmap)) {
			/* This page was touched by this vcpu in this quantum */
			private_page->age = 0;
			copy_page(private_page->original_addr,
				  private_page->private_addr);
			list_move_tail(&private_page->link, &temp_list);
		} else
			rr_age_holding_page(vrr_info, private_page);
	}

	if (!list_empty(&temp_list)) {
		/* Move the temp_list to the back of the holding_pages */
		list_splice_tail_init(&temp_list, &vrr_info->holding_pages);
	}

	/* Traverse the private_pages */
	list_for_each_entry_safe(private_page, temp,
				 &vrr_info->private_pages, link) {
		if (memslot_id(kvm, private_page->gfn) == 8) {
			private_page->age = 0;
			copy_page(private_page->original_addr,
				  private_page->private_addr);
			list_move_tail(&private_page->link,
				       &vrr_info->holding_pages);
			vrr_info->nr_private_pages--;
			vrr_info->nr_holding_pages++;
		} else {
			copy_page(private_page->original_addr,
				  private_page->private_addr);
			RR_ASSERT(rr_spte_check_pfn(*(private_page->sptep),
						    private_page->private_pfn));
			rr_spte_set_pfn(private_page->sptep,
					private_page->original_pfn);
			/* Widthdraw the write permission */
			rr_spte_withdraw_wperm(private_page->sptep);
			rr_spte_clear_cow_tag(private_page->sptep);
			kmem_cache_free(rr_priv_page_cache,
					private_page->private_addr);
			list_del(&private_page->link);
			kmem_cache_free(rr_cow_page_cache, private_page);
			vrr_info->nr_private_pages--;
		}
	}
}
#endif

#ifndef RR_HOLDING_PAGES
/* Rollback the private pages to the original ones. Called when a quantum is
 * finished and conflict with others so that have to rollback.
 */
static void rr_rollback_memory(struct kvm_vcpu *vcpu)
{
	struct rr_cow_page *private_page;
	struct rr_cow_page *temp;
	struct rr_vcpu_info *vrr_info = &vcpu->rr_info;

	list_for_each_entry_safe(private_page, temp,
				 &vrr_info->private_pages, link)
	{
		RR_ASSERT(rr_spte_check_pfn(*(private_page->sptep),
					    private_page->private_pfn));
		rr_spte_set_pfn(private_page->sptep,
				private_page->original_pfn);
		/* Widthdraw the write permission */
		rr_spte_withdraw_wperm(private_page->sptep);
		rr_spte_clear_cow_tag(private_page->sptep);

		kmem_cache_free(rr_priv_page_cache,
				private_page->private_addr);
		list_del(&private_page->link);
		kmem_cache_free(rr_cow_page_cache, private_page);
		vrr_info->nr_private_pages--;
	}
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
static void rr_rollback_memory(struct kvm_vcpu *vcpu)
{
	struct rr_cow_page *private_page;
	struct rr_cow_page *temp;
	gfn_t gfn;
	struct rr_vcpu_info *vrr_info = &vcpu->rr_info;

	/* Traverse the holding_pages */
	list_for_each_entry_safe(private_page, temp,
				 &vrr_info->holding_pages, link) {
		gfn = private_page->gfn;
#ifdef RR_ROLLBACK_PAGES
		if (re_test_bit(gfn, &vrr_info->dirty_bitmap)) {
			/* We do nothing here but keep these dirty pages in a
			 * list and copy the new content back before entering
			 * guest.
			 */
			list_move_tail(&private_page->link,
				       &vrr_info->rollback_pages);
			vrr_info->nr_holding_pages--;
			vrr_info->nr_rollback_pages++;
		} else if (re_test_bit(gfn, vrr_info->private_cb)) {
			rr_spte_set_pfn(private_page->sptep,
					private_page->original_pfn);
			rr_spte_withdraw_wperm(private_page->sptep);
			rr_spte_clear_cow_tag(private_page->sptep);
			kmem_cache_free(rr_priv_page_cache,
					private_page->private_addr);
			list_del(&private_page->link);
			kmem_cache_free(rr_cow_page_cache, private_page);
			vrr_info->nr_holding_pages--;
		} else
			rr_age_holding_page(vrr_info, private_page);
#else
		/* Whether this page has been touched by other vcpus or by
		 * this vcpu in this quantum.
		 */
		if (re_test_bit(gfn, vrr_info->private_cb) ||
		    re_test_bit(gfn, &vrr_info->dirty_bitmap)) {
			rr_spte_set_pfn(private_page->sptep,
					private_page->original_pfn);
			rr_spte_withdraw_wperm(private_page->sptep);
			rr_spte_clear_cow_tag(private_page->sptep);
			kmem_cache_free(rr_priv_page_cache,
					private_page->private_addr);
			list_del(&private_page->link);
			kmem_cache_free(rr_cow_page_cache, private_page);
			vrr_info->nr_holding_pages--;
		} else
			rr_age_holding_page(vrr_info, private_page);
#endif
	}

	/* Traverse the private_pages */
	list_for_each_entry_safe(private_page, temp,
				 &vrr_info->private_pages, link)
	{
#ifdef RR_ROLLBACK_PAGES
		/* We do nothing here but keep these dirty pages in a
		 * list and copy the new content back before entering
		 * guest.
		 */
		list_move_tail(&private_page->link,
			       &vrr_info->rollback_pages);
		vrr_info->nr_private_pages--;
		vrr_info->nr_rollback_pages++;
#else
		rr_spte_set_pfn(private_page->sptep,
				private_page->original_pfn);
		rr_spte_withdraw_wperm(private_page->sptep);
		rr_spte_clear_cow_tag(private_page->sptep);
		kmem_cache_free(rr_priv_page_cache,
				private_page->private_addr);
		list_del(&private_page->link);
		kmem_cache_free(rr_cow_page_cache, private_page);
		vrr_info->nr_private_pages--;
#endif
	}

}
#endif

/* Assume that pages committed here will never conflit with other vcpus. */
void rr_commit_again(struct kvm_vcpu *vcpu)
{
	struct kvm *kvm = vcpu->kvm;
	struct rr_kvm_info *krr_info = &kvm->rr_info;
	struct rr_vcpu_info *vrr_info = &vcpu->rr_info;
	int i;
	int online_vcpus = atomic_read(&kvm->online_vcpus);
	struct gfn_list *gfn_node, *temp;
	bool is_clean = list_empty(&vrr_info->commit_again_gfn_list);
	struct kvm_vcpu *vcpu_it;

	/* Get access_bitmap and dirty_bitmap. Clean AD bits. */
	//tm_walk_mmu(vcpu, PT_PAGE_TABLE_LEVEL);

	/* See if we really has something to commit again */
	if (is_clean) {
		return;
	}

	// Fill in dirty_bitmap
	list_for_each_entry_safe(gfn_node, temp,
				 &(vrr_info->commit_again_gfn_list),
				 link) {
		re_set_bit(gfn_node->gfn, &vrr_info->dirty_bitmap);
		list_del(&gfn_node->link);
		kmem_cache_free(rr_gfn_list_cache, gfn_node);
	}

	down_read(&krr_info->tm_rwlock);

	mutex_lock(&krr_info->tm_lock);
	/* Spread the dirty_bitmap to other vcpus's conflict_bitmap */
	for (i = 0; i < online_vcpus; ++i) {
		vcpu_it = kvm->vcpus[i];
		if (vcpu_it == vcpu)
			continue;
		RR_ASSERT(vcpu_it->vcpu_id != vcpu->vcpu_id);
		re_bitmap_or(vcpu_it->rr_info.public_cb,
			     &vrr_info->dirty_bitmap);
	}
	/* Copy conflict_bitmap */
	swap(vrr_info->private_cb, vrr_info->public_cb);

	/* Commit memory here */
	rr_commit_memory(vcpu);

	mutex_unlock(&krr_info->tm_lock);

	up_read(&krr_info->tm_rwlock);

	/* Reset bitmaps */
	re_bitmap_clear(&vrr_info->access_bitmap);
	re_bitmap_clear(&vrr_info->dirty_bitmap);
	re_bitmap_clear(vrr_info->private_cb);

	vrr_info->tlb_flush = true;
	return;
}
EXPORT_SYMBOL_GPL(rr_commit_again);

static void rr_vcpu_insert_chunk_list(struct kvm_vcpu *vcpu)
{
	struct rr_kvm_info *krr_info = &vcpu->kvm->rr_info;

	spin_lock(&krr_info->chunk_list_lock);
	list_add_tail(&vcpu->rr_info.chunk_info.link, &krr_info->chunk_list);
	spin_unlock(&krr_info->chunk_list_lock);
}

static void rr_vcpu_set_chunk_state(struct kvm_vcpu *vcpu, int state)
{
	struct rr_kvm_info *krr_info = &vcpu->kvm->rr_info;

	spin_lock(&krr_info->chunk_list_lock);
	vcpu->rr_info.chunk_info.state = state;
	spin_unlock(&krr_info->chunk_list_lock);
}

static void rr_vcpu_chunk_list_check_and_del(struct kvm_vcpu *vcpu)
{
	struct rr_kvm_info *krr_info = &vcpu->kvm->rr_info;
	struct list_head *head = &krr_info->chunk_list;
	struct rr_chunk_info *chunk, *temp;
	bool can_leave;
retry:
	can_leave = true;
	spin_lock(&krr_info->chunk_list_lock);
	list_for_each_entry_safe(chunk, temp, head, link) {
		if (chunk->vcpu_id == vcpu->vcpu_id) {
			/* We reach our own chunk node, which means that we
			 * can delete this node and enter guest.
			 */
			list_del(&chunk->link);
			chunk->state = RR_CHUNK_STATE_IDLE;
			break;
		}
		if (chunk->action == RR_CHUNK_COMMIT &&
		    chunk->state != RR_CHUNK_STATE_FINISHED) {
			/* There is one vcpu before us and it is going to
			 * commit, so we need to wait for it.
			 */
			can_leave = false;
			break;
		}
	}
	spin_unlock(&krr_info->chunk_list_lock);
	if (!can_leave) {
		goto retry;
	}
}

#ifdef RR_ROLLBACK_PAGES
/* Update pages of the rollback_pages list from the public memory */
static void rr_copy_rollback_pages(struct kvm_vcpu *vcpu)
{
	struct rr_cow_page *private_page, *temp;
	struct rr_vcpu_info *vrr_info = &vcpu->rr_info;

	list_for_each_entry_safe(private_page, temp,
				 &vrr_info->rollback_pages, link) {
		private_page->age = 0;
		copy_page(private_page->private_addr,
			  private_page->original_addr);
		list_move_tail(&private_page->link,
			       &vrr_info->holding_pages);
		vrr_info->nr_rollback_pages--;
		vrr_info->nr_holding_pages++;
	}
}
#endif

void rr_post_check(struct kvm_vcpu *vcpu)
{
#ifdef RR_ROLLBACK_PAGES
	bool is_rollback = (vcpu->rr_info.chunk_info.action == RR_CHUNK_ROLLBACK);
#endif

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
	struct rr_vcpu_info *vrr_info = &apic->vcpu->rr_info;
	struct rr_event *rr_event;

	if (vrr_info->enabled) {
		mutex_lock(&(vrr_info->events_list_lock));
		rr_event = kmem_cache_alloc(rr_event_cache, GFP_KERNEL);
		if (unlikely(!rr_event)) {
			RR_ERR("error: failed to kmem_cache_alloc() for "
			       "rr_event");
			mutex_unlock(&(vrr_info->events_list_lock));
			goto out;
		}

		rr_event->delivery_mode = delivery_mode;
		rr_event->vector = vector;
		rr_event->level = level;
		rr_event->trig_mode = trig_mode;
		rr_event->dest_map = dest_map;
		list_add(&(rr_event->link), &(vrr_info->events_list));
		mutex_unlock(&(vrr_info->events_list_lock));
	}
out:
	return apic_accept_irq_without_record(apic, delivery_mode, vector,
					      level, trig_mode, dest_map);
}
EXPORT_SYMBOL_GPL(rr_apic_accept_irq);

void rr_apic_reinsert_irq(struct kvm_vcpu *vcpu)
{
	struct rr_event *e, *tmp;
	struct rr_vcpu_info *vrr_info = &vcpu->rr_info;

	mutex_lock(&(vrr_info->events_list_lock));
	list_for_each_entry_safe(e, tmp, &(vrr_info->events_list), link) {
		apic_accept_irq_without_record(vcpu->arch.apic,
					       e->delivery_mode,
					       e->vector, e->level,
					       e->trig_mode, e->dest_map);
	}
	mutex_unlock(&(vrr_info->events_list_lock));
}
EXPORT_SYMBOL_GPL(rr_apic_reinsert_irq);

static void  __rr_set_AD_bit(struct kvm_vcpu *vcpu, u64 *sptep, gpa_t gpa, hpa_t addr)
{
	gfn_t gfn;
	bool accessed = *sptep & VMX_EPT_ACCESS_BIT;
	bool dirty;

#ifdef DEBUG_RECORD_REPLAY
	dirty = *sptep & VMX_EPT_DIRTY_BIT;
	RR_ASSERT(accessed || !dirty);
#endif
	if (accessed) {
		gfn = gpa >> PAGE_SHIFT;
		dirty = *sptep & VMX_EPT_DIRTY_BIT;
		re_set_bit(gfn, &vcpu->rr_info.access_bitmap);
		if (dirty) {
			re_set_bit(gfn, &vcpu->rr_info.dirty_bitmap);
		}
		*sptep &= ~(VMX_EPT_ACCESS_BIT | VMX_EPT_DIRTY_BIT);
	}
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

static void rr_gen_bitmap_from_spt(struct kvm_vcpu *vcpu)
{
	int level = vcpu->arch.mmu.shadow_root_level;
	hpa_t shadow_addr = vcpu->arch.mmu.root_hpa;

	RR_ASSERT(level == PT64_ROOT_LEVEL);
	RR_ASSERT((vcpu->arch.mmu.root_level == PT64_ROOT_LEVEL) &&
		  vcpu->arch.mmu.direct_map);
	__rr_walk_spt(vcpu, shadow_addr, level, 0);
}

static inline int rr_detect_conflict(struct region_bitmap *access_bm,
				     struct region_bitmap *conflict_bm)
{
	/* Notice the order of the arguments */
	return re_bitmap_intersects(conflict_bm, access_bm);
}

static void rr_log_chunk(struct kvm_vcpu *vcpu)
{
	struct rr_kvm_info *krr_info = &vcpu->kvm->rr_info;
	unsigned long rcx, rip;

	if (vcpu->vcpu_id == krr_info->last_record_vcpu)
		return;
	rcx = kvm_register_read(vcpu, VCPU_REGS_RCX);
	rip = vmcs_readl(GUEST_RIP);
	krr_info->last_record_vcpu = vcpu->vcpu_id;
	/* get_random_bytes(&bc, sizeof(unsigned int)); */
	/* The last argument should be the bc */
	RR_LOG("%d %lx %lx %x\n", vcpu->vcpu_id, rip, rcx, 0);
}

static int rr_ape_check_chunk(struct kvm_vcpu *vcpu, int early_rollback)
{
	struct kvm *kvm = vcpu->kvm;
	struct rr_kvm_info *krr_info = &kvm->rr_info;
	struct rr_vcpu_info *vrr_info = &vcpu->rr_info;
	int i;
	int online_vcpus = atomic_read(&(kvm->online_vcpus));
	int commit = 1;
	struct kvm_vcpu *vcpu_it;

	RR_ASSERT(vrr_info->enabled);
	rr_gen_bitmap_from_spt(vcpu);
	if (!vrr_info->exclusive_commit &&
	    atomic_read(&krr_info->normal_commit) < 1) {
		/* Now anothter vcpu is in exclusive commit state */
		if (wait_event_interruptible(krr_info->exclu_commit_que,
		    atomic_read(&krr_info->normal_commit) == 1)) {
			RR_ERR("error: vcpu=%d wait_event_interruptible() "
			       "interrupted", vcpu->vcpu_id);
			commit = -1;
			goto out;
		}
	}

	down_read(&(krr_info->tm_rwlock));
	mutex_lock(&(krr_info->tm_lock));
	if (krr_info->last_commit_vcpu != vcpu->vcpu_id) {
		/* Detect conflict */
		if (early_rollback ||
		    rr_detect_conflict(&vrr_info->access_bitmap,
				       vrr_info->public_cb)) {
			commit = 0;
		}
	}

	if (commit) {
		if (vrr_info->exclusive_commit) {
			/* Exclusive commit state */
			vrr_info->exclusive_commit = 0;
			atomic_set(&krr_info->normal_commit, 1);
			wake_up_interruptible(&krr_info->exclu_commit_que);
		} else if (atomic_read(&krr_info->normal_commit) < 1) {
			/* Now another vcpu is in exclusive commit state,
			 * need to rollback.
			 */
			commit = 0;
			goto rollback;
		}
		/* Set dirty bitmap */
		for (i = 0; i < online_vcpus; ++i) {
			vcpu_it = kvm->vcpus[i];
			if (vcpu_it == vcpu)
				continue;
			re_bitmap_or(vcpu_it->rr_info.public_cb,
				     &vrr_info->dirty_bitmap);
		}

		krr_info->last_commit_vcpu = vcpu->vcpu_id;
		vrr_info->nr_rollback = 0;
		rr_log_chunk(vcpu);
	} else {
rollback:
		vrr_info->nr_rollback++;
		if (!vrr_info->exclusive_commit &&
		    vrr_info->nr_rollback >= RR_CONSEC_RB_TIME) {
			if (atomic_dec_and_test(&krr_info->normal_commit)) {
				/* Now we can enter exclusive commit state */
				vrr_info->exclusive_commit = 1;
			}
		}
	}
	/* Insert chunk_info to rr_info->chunk_list */
	vrr_info->chunk_info.action = commit ? RR_CHUNK_COMMIT : RR_CHUNK_ROLLBACK;
	vrr_info->chunk_info.state = RR_CHUNK_STATE_BUSY;
	rr_vcpu_insert_chunk_list(vcpu);

	swap(vrr_info->public_cb, vrr_info->private_cb);
	mutex_unlock(&(krr_info->tm_lock));

	if (commit) {
		rr_commit_memory(vcpu);
	} else rr_rollback_memory(vcpu);

	rr_vcpu_set_chunk_state(vcpu, RR_CHUNK_STATE_FINISHED);

	up_read(&(krr_info->tm_rwlock));

	/* Reset bitmaps */
	re_bitmap_clear(&vrr_info->access_bitmap);
	re_bitmap_clear(&vrr_info->dirty_bitmap);
	re_bitmap_clear(vrr_info->private_cb);

	vmcs_write32(VMX_PREEMPTION_TIMER_VALUE, rr_ctrl.timer_value);
out:
	vrr_info->tlb_flush = true;
	return commit;
}

int rr_check_chunk(struct kvm_vcpu *vcpu)
{
	u32 exit_reason = rr_ops->get_vmx_exit_reason(vcpu);
	struct rr_vcpu_info *vrr_info = &vcpu->rr_info;
	int ret;
	int early_rollback = 0;

	#ifdef RR_EARLY_ROLLBACK
	if (exit_reason == EXIT_REASON_EPT_VIOLATION) {
		gfn_t gfn = vmcs_read64(GUEST_PHYSICAL_ADDRESS) >> PAGE_SHIFT;
		if (re_test_bit(gfn, vrr_info->public_cb)) {
			exit_reason = EXIT_REASON_PREEMPTION_TIMER;
			early_rollback = 1;
		}
	}
	#endif

	#ifdef RR_EARLY_CHECK
	if (exit_reason == EXIT_REASON_EPT_VIOLATION) {
		gfn_t gfn = vmcs_read64(GUEST_PHYSICAL_ADDRESS) >> PAGE_SHIFT;
		if (re_test_bit(gfn, vrr_info->public_cb)) {
			exit_reason = EXIT_REASON_PREEMPTION_TIMER;
		}
	}
	#endif
	if (exit_reason != EXIT_REASON_EPT_VIOLATION
	    && exit_reason != EXIT_REASON_PAUSE_INSTRUCTION) {
		ret = rr_ape_check_chunk(vcpu, early_rollback);
		if (ret == -1) {
			RR_ERR("error: vcpu=%d rr_ape_check_chunk() returns -1",
			       vcpu->vcpu_id);
		} else if (ret == 1) {
			rr_make_request(RR_REQ_COMMIT_AGAIN, vrr_info);
			rr_make_request(RR_REQ_POST_CHECK, vrr_info);
			rr_make_request(RR_REQ_CHECKPOINT, vrr_info);
			return RR_CHUNK_COMMIT;
		} else {
			rr_make_request(RR_REQ_POST_CHECK, vrr_info);
			return RR_CHUNK_ROLLBACK;
		}
	}

	return RR_CHUNK_SKIP;
}
EXPORT_SYMBOL_GPL(rr_check_chunk);

static void rr_clear_holding_pages(struct kvm_vcpu *vcpu)
{
	struct rr_cow_page *private_page;
	struct rr_cow_page *temp;
	struct rr_vcpu_info *vrr_info = &vcpu->rr_info;

	list_for_each_entry_safe(private_page, temp,
				 &vrr_info->holding_pages,
				 link) {
		rr_spte_set_pfn(private_page->sptep,
				private_page->original_pfn);
		rr_spte_withdraw_wperm(private_page->sptep);
		rr_spte_clear_cow_tag(private_page->sptep);
		kmem_cache_free(rr_priv_page_cache,
				private_page->private_addr);
		list_del(&private_page->link);
		kmem_cache_free(rr_cow_page_cache, private_page);
		vrr_info->nr_holding_pages--;
	}
}

#ifdef RR_ROLLBACK_PAGES
static void rr_clear_rollback_pages(struct kvm_vcpu *vcpu)
{
	struct rr_cow_page *private_page;
	struct rr_cow_page *temp;
	struct rr_vcpu_info *vrr_info = &vcpu->rr_info;

	list_for_each_entry_safe(private_page, temp,
				 &vrr_info->rollback_pages,
				 link) {
		rr_spte_set_pfn(private_page->sptep,
				private_page->original_pfn);
		rr_spte_withdraw_wperm(private_page->sptep);
		rr_spte_clear_cow_tag(private_page->sptep);
		kmem_cache_free(rr_priv_page_cache,
				private_page->private_addr);
		list_del(&private_page->link);
		kmem_cache_free(rr_cow_page_cache, private_page);
		vrr_info->nr_rollback_pages--;
	}
}
#endif

static int __rr_ape_disable(struct kvm_vcpu *vcpu)
{
	struct rr_kvm_info *krr_info = &vcpu->kvm->rr_info;
	struct rr_vcpu_info *vrr_info = &vcpu->rr_info;
	struct rr_event *eve, *eve_tmp;
	struct gfn_list *gfn_node, *gfn_tmp;

	if (vrr_info->is_master) {
		struct rr_chunk_info *chunk, *temp;

		/* Release rr_kvm_info */
		krr_info->enabled = false;

		while (krr_info->dma_holding_sem) {
			RR_DLOG(INIT, "DMA is holding sem, waiting");
			msleep(1);
		}

		spin_lock(&krr_info->chunk_list_lock);
		/* Release chunk_list */
		list_for_each_entry_safe(chunk, temp, &krr_info->chunk_list,
					 link) {
			list_del(&chunk->link);
		}
		spin_unlock(&krr_info->chunk_list_lock);
		krr_info->last_commit_vcpu = -1;
		atomic_set(&krr_info->normal_commit, 1);
		krr_info->last_record_vcpu = -1;
	}

	vrr_info->enabled = false;
	rr_clear_all_request(vrr_info);
	vrr_info->nr_rollback = 0;
	vrr_info->tlb_flush = false;

	/* Release events_list */
	mutex_lock(&vrr_info->events_list_lock);
	list_for_each_entry_safe(eve, eve_tmp, &vrr_info->events_list, link) {
		list_del(&eve->link);
		kmem_cache_free(rr_event_cache, eve);
	}
	mutex_unlock(&vrr_info->events_list_lock);

	/* Release commit_again_gfn_list */
	list_for_each_entry_safe(gfn_node, gfn_tmp,
				 &vrr_info->commit_again_gfn_list, link) {
		list_del(&gfn_node->link);
		kmem_cache_free(rr_gfn_list_cache, gfn_node);
	}

	/* Release bitmap */
	re_bitmap_destroy(&vrr_info->access_bitmap);
	re_bitmap_destroy(&vrr_info->conflict_bitmap_1);
	re_bitmap_destroy(&vrr_info->conflict_bitmap_2);
	re_bitmap_destroy(&vrr_info->dirty_bitmap);
	vrr_info->public_cb = &vrr_info->conflict_bitmap_1;
	vrr_info->private_cb = &vrr_info->conflict_bitmap_2;

	rr_clear_holding_pages(vcpu);
#ifdef RR_ROLLBACK_PAGES
	rr_clear_rollback_pages(vcpu);
	RR_ASSERT(vrr_info->nr_rollback_pages == 0);
#endif
	RR_ASSERT(vrr_info->nr_private_pages == 0);
	RR_ASSERT(vrr_info->nr_holding_pages == 0);

	rr_ops->ape_vmx_clear();

	RR_DLOG(INIT, "vcpu=%d disabled", vcpu->vcpu_id);

	return 0;
}

static int __rr_ape_post_disable(struct kvm_vcpu *vcpu)
{
	RR_DLOG(INIT, "vcpu=%d");
	RR_ASSERT(vcpu->rr_info.is_master);
	/* Release kmem cache */
	if (rr_cow_page_cache) {
		kmem_cache_destroy(rr_cow_page_cache);
		rr_cow_page_cache = NULL;
	}
	if (rr_priv_page_cache) {
		kmem_cache_destroy(rr_priv_page_cache);
		rr_priv_page_cache = NULL;
	}
	if (rr_event_cache) {
		kmem_cache_destroy(rr_event_cache);
		rr_event_cache = NULL;
	}
	if (rr_gfn_list_cache) {
		kmem_cache_destroy(rr_gfn_list_cache);
		rr_gfn_list_cache = NULL;
	}

	vcpu->kvm->arch.mmu_valid_gen++;

	return 0;
}

void rr_vcpu_disable(struct kvm_vcpu *vcpu)
{
	struct rr_vcpu_info *vrr_info = &vcpu->rr_info;

	RR_DLOG(INIT, "vcpu=%d start", vcpu->vcpu_id);
	if (vrr_info->exclusive_commit) {
		/* Wake up other vcpus */
		vrr_info->exclusive_commit = 0;
		atomic_set(&vcpu->kvm->rr_info.normal_commit, 1);
		wake_up_interruptible(&vcpu->kvm->rr_info.exclu_commit_que);
	}
	__rr_vcpu_sync(vcpu, __rr_ape_disable, __rr_ape_disable,
		       __rr_ape_post_disable);

	kvm_mmu_unload(vcpu);
	kvm_mmu_reload(vcpu);
	kvm_make_request(KVM_REQ_TLB_FLUSH, vcpu);

	RR_DLOG(INIT, "vcpu=%d finish", vcpu->vcpu_id);
	printk(KERN_INFO "vcpu=%d disabled\n", vcpu->vcpu_id);
}
EXPORT_SYMBOL_GPL(rr_vcpu_disable);

