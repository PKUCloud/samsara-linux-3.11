#include <linux/record_replay.h>
#include <linux/kvm_host.h>
#include <linux/delay.h>
#include <asm/logger.h>
#include <asm/vmx.h>
#include <asm/checkpoint_rollback.h>

#include "mmu.h"
#include "lapic.h"
#include "rr_hash.h"

struct rr_ops *rr_ops;
/* Cache for struct rr_cow_page */
struct kmem_cache *rr_cow_page_cache;
/* Cache for a private page of memory */
struct kmem_cache *rr_priv_page_cache;
/* Cache for struct rr_event */
struct kmem_cache *rr_event_cache;

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

	RR_DLOG(INIT, "kmem_cache initialized");
out:
	return;

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
	rr_init_hash(&rr_info->cow_hash);
	re_bitmap_init(&rr_info->access_bitmap);
	re_bitmap_init(&rr_info->dirty_bitmap);
	re_bitmap_init(&rr_info->conflict_bitmap_1);
	re_bitmap_init(&rr_info->conflict_bitmap_2);
	rr_info->public_cb = &rr_info->conflict_bitmap_1;
	rr_info->private_cb = &rr_info->conflict_bitmap_2;
	rr_info->exclusive_commit = 0;
	rr_info->nr_rollback = 0;
	rr_info->nr_chunk = 0;
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
	memset(rr_info->exit_stat, 0, sizeof(rr_info->exit_stat));
	rr_info->nr_chunk_rollback = 0;
	rr_info->nr_chunk_commit = 0;
	rr_info->exit_time = 0;
	rr_info->cur_exit_time = 0;
	rr_info->tlb_flush = true;
	rr_info->nr_exits = 0;
	rr_info->enabled = true;
	rr_info->commit_again_clean = true;
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
	atomic_set(&rr_kvm_info->normal_commit, 1);
	rr_kvm_info->last_record_vcpu = -1;
	rr_kvm_info->dma_holding_sem = false;
	init_rwsem(&rr_kvm_info->tm_rwlock);
	init_waitqueue_head(&rr_kvm_info->exclu_commit_que);
	rr_kvm_info->disabled_time = 0;
	rdtscll(rr_kvm_info->enabled_time);
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
	unsigned long rip = vcpu->arch.regs[VCPU_REGS_RIP];
	unsigned long rcx = vcpu->arch.regs[VCPU_REGS_RCX];

	list_for_each_entry_safe(e, tmp, &rr_info->events_list, link) {
		RR_LOG("2 %d %d %d %d %llx %d %llx\n",
		       e->delivery_mode, e->vector, e->level,
		       e->trig_mode, rip, 0, rcx);
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

/* Called when fixing a page fault. */
void rr_fix_cow_page(struct rr_cow_page *cow_page, u64 *sptep)
{
	pfn_t pfn = (*sptep & PT64_BASE_ADDR_MASK) >> PAGE_SHIFT;

	RR_ASSERT(sptep == cow_page->sptep);
	cow_page->original_pfn = pfn;
	cow_page->original_addr = pfn_to_kaddr(pfn);
	rr_spte_set_pfn(sptep, cow_page->private_pfn);
	rr_spte_set_cow_tag(sptep);
	RR_DLOG(MMU, "warning: fix gfn=0x%llx", cow_page->gfn);
}
EXPORT_SYMBOL_GPL(rr_fix_cow_page);

struct rr_cow_page *rr_check_cow_page(struct rr_vcpu_info *vrr_info, gfn_t gfn)
{
	return rr_hash_find(vrr_info->cow_hash, gfn);
}
EXPORT_SYMBOL_GPL(rr_check_cow_page);

/* Separate memory with copy-on-write
 * Alloc a new page to replace the original page and update the spte, then add
 * an item to vcpu->arch.private_pages list.
 */
void rr_memory_cow(struct kvm_vcpu *vcpu, u64 *sptep, pfn_t pfn, gfn_t gfn)
{
	void *new_page;
	struct rr_cow_page *private_mem_page;
	struct rr_vcpu_info *vrr_info = &vcpu->rr_info;

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
	private_mem_page->state = RR_COW_STATE_PRIVATE;
	copy_page(new_page, private_mem_page->original_addr);
	rr_spte_set_pfn(sptep, private_mem_page->private_pfn);
	rr_spte_set_cow_tag(sptep);

	/* Add it to the list */
	list_add(&private_mem_page->link, &vrr_info->private_pages);
	(vrr_info->nr_private_pages)++;
	rr_hash_insert(vrr_info->cow_hash, private_mem_page);
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
	private_mem_page->state = RR_COW_STATE_PRIVATE;
	copy_page(new_page, private_mem_page->original_addr);
	rr_spte_set_pfn(sptep, private_mem_page->private_pfn);
	rr_spte_set_cow_tag(sptep);
	*sptep |= PT_WRITABLE_MASK;

	/* Add it to the list */
	list_add(&private_mem_page->link, &vrr_info->private_pages);
	vrr_info->nr_private_pages++;
	rr_hash_insert(vrr_info->cow_hash, private_mem_page);

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
	u64 spte;

	RR_ASSERT(level == PT64_ROOT_LEVEL);
	RR_ASSERT(shadow_addr != INVALID_PAGE);

	for (; level >= PT_PAGE_TABLE_LEVEL; --level) {
		index = SHADOW_PT_INDEX(addr, level);
		sptep = ((u64 *)__va(shadow_addr)) + index;
		spte = *sptep;
		if (unlikely(!is_shadow_present_pte(spte))) {
			return -1;
		}
		*sptep &= ~(VMX_EPT_ACCESS_BIT);
		if (is_last_spte(spte, level)) {
			*sptep &= ~(VMX_EPT_DIRTY_BIT);
			return 0;
		}
		shadow_addr = spte & PT64_BASE_ADDR_MASK;
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
		vrr_info->tlb_flush = true;
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

	if (rr_check_request(RR_REQ_COMMIT_AGAIN, vrr_info)) {
		if (write) {
			vrr_info->commit_again_clean = false;
			re_set_bit(gfn, &vrr_info->dirty_bitmap);
		}
		rr_clear_AD_bit_by_gfn(vcpu, gfn);
	}
	return kaddr;
}
EXPORT_SYMBOL_GPL(rr_ept_gfn_to_kaddr);

/* Before accessing the original pfn of the cow_page, we need to check that
 * if that spte was dropped. If so, we need to reconstruct it and get the
 * new correct original pfn.
 */
static void rr_check_cow_page_before_access(struct kvm_vcpu *vcpu,
					    struct rr_cow_page *cow_page)
{
	u64 *sptep = cow_page->sptep;
	pfn_t pfn = (*sptep & PT64_BASE_ADDR_MASK) >> PAGE_SHIFT;
	int r;
	gpa_t gpa;

	if (pfn != cow_page->private_pfn) {
		RR_DLOG(MMU, "vcpu=%d find mismatch gfn=0x%llx spte=0x%llx",
			vcpu->vcpu_id, cow_page->gfn, *sptep);
		RR_ASSERT(*sptep == 0);
		vcpu->rr_info.tlb_flush = true;
		gpa = gfn_to_gpa(cow_page->gfn);
		while (*sptep == 0) {
			r = tdp_page_fault(vcpu, gpa, PFERR_WRITE_MASK,
					   false);
			if (unlikely(r < 0)) {
				RR_ERR("error: vcpu=%d tdp_page_fault failed "
				       "for gfn=0x%llx r=%d", vcpu->vcpu_id,
				       cow_page->gfn, r);
				return;
			}
		}
	}
}

/* Restore the spte of a rr_cow_page. We need to check if that spte has been
 * dropped before restoring.
 */
static __always_inline void rr_spte_restore(struct rr_cow_page *cow_page)
{
	u64 *sptep = cow_page->sptep;

	if (*sptep == 0) {
		RR_DLOG(MMU, "skip dropped spte for gfn=0x%llx",
			cow_page->gfn);
		return;
	}

	rr_spte_set_pfn(sptep, cow_page->original_pfn);
	rr_spte_withdraw_wperm(sptep);
	rr_spte_clear_cow_tag(sptep);
}

static inline void rr_age_holding_page(struct rr_vcpu_info *vrr_info,
				       struct rr_cow_page *private_page,
				       u64 target_chunk_num)
{
	if (private_page->chunk_num < target_chunk_num) {
		rr_spte_restore(private_page);
		kmem_cache_free(rr_priv_page_cache,
				private_page->private_addr);
		list_del(&private_page->link);
		hlist_del(&private_page->hlink);
		kmem_cache_free(rr_cow_page_cache, private_page);
		vrr_info->nr_holding_pages--;
	}
}

static inline void rr_commit_holding_pages_by_list(struct kvm_vcpu *vcpu)
{
	struct rr_cow_page *private_page;
	struct rr_cow_page *temp;
	gfn_t gfn;
	struct rr_vcpu_info *vrr_info = &vcpu->rr_info;
	struct list_head *head = &vrr_info->holding_pages;
	struct region_bitmap *conflict_bm = vrr_info->private_cb;
	struct region_bitmap *dirty_bm = &vrr_info->dirty_bitmap;
	u64 nr_chunk = vrr_info->nr_chunk;
	u64 chunk_num = (nr_chunk > RR_MAX_HOLDING_PAGE_AGE) ?
			(nr_chunk - RR_MAX_HOLDING_PAGE_AGE) : 0;

	/* Traverse the holding_pages */
	list_for_each_entry_safe(private_page, temp, head, link) {
		gfn = private_page->gfn;
		/* Whether this page has been touched by other vcpus */
		if (re_test_bit(gfn, conflict_bm)) {
			rr_spte_restore(private_page);
			kmem_cache_free(rr_priv_page_cache,
					private_page->private_addr);
			list_del(&private_page->link);
			hlist_del(&private_page->hlink);
			kmem_cache_free(rr_cow_page_cache, private_page);
			vrr_info->nr_holding_pages--;
		} else if (re_test_bit(gfn, dirty_bm)) {
			/* This page was touched by this vcpu in this quantum */
			private_page->chunk_num = nr_chunk;
			rr_check_cow_page_before_access(vcpu, private_page);
			copy_page(private_page->original_addr,
				  private_page->private_addr);
		} else
			rr_age_holding_page(vrr_info, private_page,
					    chunk_num);
	}
}

/* Commit holding_pages and private_pages indexed by bitmap */
static inline void rr_commit_cow_pages_by_bitmap(struct kvm_vcpu *vcpu)
{
	struct rr_cow_page *cow_page;
	struct rr_vcpu_info *vrr_info = &vcpu->rr_info;
	struct hlist_head *cow_hash = vrr_info->cow_hash;
	unsigned long *pgfn, *tmp;
	u64 nr_chunk = vrr_info->nr_chunk;
	struct kvm *kvm = vcpu->kvm;
	struct list_head *holding_head = &vrr_info->holding_pages;

	re_bitmap_for_each_bit(pgfn, tmp, vrr_info->private_cb) {
		cow_page = rr_hash_find(cow_hash, *pgfn);
		if (cow_page) {
			RR_ASSERT(cow_page->state == RR_COW_STATE_HOLDING);
			rr_spte_restore(cow_page);
			kmem_cache_free(rr_priv_page_cache,
					cow_page->private_addr);
			list_del(&cow_page->link);
			hlist_del(&cow_page->hlink);
			kmem_cache_free(rr_cow_page_cache, cow_page);
			vrr_info->nr_holding_pages--;
		}
	}

	re_bitmap_for_each_bit(pgfn, tmp, &vrr_info->dirty_bitmap) {
		cow_page = rr_hash_find(cow_hash, *pgfn);
		if (likely(cow_page)) {
			cow_page->chunk_num = nr_chunk;
			rr_check_cow_page_before_access(vcpu, cow_page);
			copy_page(cow_page->original_addr,
				  cow_page->private_addr);
			if (cow_page->state == RR_COW_STATE_PRIVATE) {
				if (memslot_id(kvm, cow_page->gfn) == 8) {
					cow_page->state = RR_COW_STATE_HOLDING;
					list_move_tail(&cow_page->link,
						       holding_head);
					vrr_info->nr_private_pages--;
					vrr_info->nr_holding_pages++;
				} else {
					rr_spte_restore(cow_page);
					kmem_cache_free(rr_priv_page_cache,
							cow_page->private_addr);
					list_del(&cow_page->link);
					hlist_del(&cow_page->hlink);
					kmem_cache_free(rr_cow_page_cache,
							cow_page);
					vrr_info->nr_private_pages--;
				}
			}
		} else {
			RR_ERR("error: vcpu=%d gfn=0x%lx in dirty_bitmap "
			       "but not in cow pages", vcpu->vcpu_id, *pgfn);
		}
	}
	RR_ASSERT(list_empty(&vrr_info->private_pages));
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
	struct rr_vcpu_info *vrr_info = &vcpu->rr_info;
	struct kvm *kvm = vcpu->kvm;
	struct list_head *head = &vrr_info->private_pages;
	int diff = re_bitmap_size(vrr_info->private_cb) +
		   re_bitmap_size(&vrr_info->dirty_bitmap) -
		   vrr_info->nr_holding_pages - vrr_info->nr_private_pages;
	u64 nr_chunk = vrr_info->nr_chunk;
	struct list_head *holding_head = &vrr_info->holding_pages;

	if (diff <= 0) {
		rr_commit_cow_pages_by_bitmap(vcpu);
		return;
	}

	rr_commit_holding_pages_by_list(vcpu);

	/* Traverse the private_pages */
	list_for_each_entry_safe(private_page, temp, head, link) {
		if (memslot_id(kvm, private_page->gfn) == 8) {
			private_page->chunk_num = nr_chunk;
			rr_check_cow_page_before_access(vcpu, private_page);
			copy_page(private_page->original_addr,
				  private_page->private_addr);
			private_page->state = RR_COW_STATE_HOLDING;
			list_move_tail(&private_page->link,
				       holding_head);
			vrr_info->nr_private_pages--;
			vrr_info->nr_holding_pages++;
		} else {
			rr_check_cow_page_before_access(vcpu, private_page);
			copy_page(private_page->original_addr,
				  private_page->private_addr);
			rr_spte_restore(private_page);
			kmem_cache_free(rr_priv_page_cache,
					private_page->private_addr);
			list_del(&private_page->link);
			hlist_del(&private_page->hlink);
			kmem_cache_free(rr_cow_page_cache, private_page);
			vrr_info->nr_private_pages--;
		}
	}
}

/* Only commit the dirty_bitmap. Conflict bitmap will be left to be handled
 * next chunk.
 * There may be one more cow page left in the private_pages after iterating
 * the dirty bitmap because of the early check. We just ignore it and let it
 * to be handled next chunk.
 */
static void rr_commit_memory_again(struct kvm_vcpu *vcpu)
{
	struct rr_cow_page *cow_page;
	struct rr_vcpu_info *vrr_info = &vcpu->rr_info;
	struct hlist_head *cow_hash = vrr_info->cow_hash;
	unsigned long *pgfn, *tmp;
	struct kvm *kvm = vcpu->kvm;
	struct list_head *holding_head = &vrr_info->holding_pages;
	u64 nr_chunk = vrr_info->nr_chunk;

	re_bitmap_for_each_bit(pgfn, tmp, &vrr_info->dirty_bitmap) {
		cow_page = rr_hash_find(cow_hash, *pgfn);
		RR_ASSERT(cow_page);
		cow_page->chunk_num = nr_chunk;
		rr_check_cow_page_before_access(vcpu, cow_page);
		copy_page(cow_page->original_addr,
			  cow_page->private_addr);
		if (cow_page->state == RR_COW_STATE_PRIVATE) {
			if (memslot_id(kvm, *pgfn) == 8) {
				cow_page->state = RR_COW_STATE_HOLDING;
				list_move_tail(&cow_page->link, holding_head);
				vrr_info->nr_private_pages--;
				vrr_info->nr_holding_pages++;
			} else {
				rr_spte_restore(cow_page);
				kmem_cache_free(rr_priv_page_cache,
						cow_page->private_addr);
				list_del(&cow_page->link);
				hlist_del(&cow_page->hlink);
				kmem_cache_free(rr_cow_page_cache, cow_page);
				vrr_info->nr_private_pages--;
			}
		}
	}
	RR_ASSERT(vrr_info->nr_private_pages <= 1);
}

static inline void rr_rollback_holding_pages_by_list(struct rr_vcpu_info *vrr_info)
{
	struct rr_cow_page *private_page;
	struct rr_cow_page *temp;
	gfn_t gfn;
	struct list_head *head = &vrr_info->holding_pages;
	struct region_bitmap *dirty_bm = &vrr_info->dirty_bitmap;
	struct region_bitmap *conflict_bm = vrr_info->private_cb;
	u64 chunk_num = (vrr_info->nr_chunk > RR_MAX_HOLDING_PAGE_AGE) ?
			(vrr_info->nr_chunk - RR_MAX_HOLDING_PAGE_AGE) : 0;
	struct list_head *rollback_head = &vrr_info->rollback_pages;

	/* Traverse the holding_pages */
	list_for_each_entry_safe(private_page, temp, head, link) {
		gfn = private_page->gfn;
#ifdef RR_ROLLBACK_PAGES
		if (re_test_bit(gfn, dirty_bm)) {
			/* We do nothing here but keep these dirty pages in a
			 * list and copy the new content back before entering
			 * guest.
			 */
			private_page->state = RR_COW_STATE_ROLLBACK;
			list_move_tail(&private_page->link, rollback_head);
			vrr_info->nr_holding_pages--;
			vrr_info->nr_rollback_pages++;
		} else if (re_test_bit(gfn, conflict_bm)) {
			rr_spte_restore(private_page);
			kmem_cache_free(rr_priv_page_cache,
					private_page->private_addr);
			list_del(&private_page->link);
			hlist_del(&private_page->hlink);
			kmem_cache_free(rr_cow_page_cache, private_page);
			vrr_info->nr_holding_pages--;
		} else
			rr_age_holding_page(vrr_info, private_page, chunk_num);
#else
		/* Whether this page has been touched by other vcpus or by
		 * this vcpu in this quantum.
		 */
		if (re_test_bit(gfn, conflict_bm) ||
		    re_test_bit(gfn, dirty_bm)) {
			rr_spte_restore(private_page);
			kmem_cache_free(rr_priv_page_cache,
					private_page->private_addr);
			list_del(&private_page->link);
			hlist_del(&private_page->hlink);
			kmem_cache_free(rr_cow_page_cache, private_page);
			vrr_info->nr_holding_pages--;
		} else
			rr_age_holding_page(vrr_info, private_page, chunk_num);
#endif
	}
}

static inline void rr_rollback_cow_pages_by_bitmap(struct rr_vcpu_info *vrr_info)
{
	struct rr_cow_page *cow_page;
	struct hlist_head *cow_hash = vrr_info->cow_hash;
	unsigned long *pgfn, *tmp;
	struct list_head *rollback_head = &vrr_info->rollback_pages;

	re_bitmap_for_each_bit(pgfn, tmp, &vrr_info->dirty_bitmap) {
		cow_page = rr_hash_find(cow_hash, *pgfn);
		if (likely(cow_page)) {
			if (cow_page->state == RR_COW_STATE_HOLDING)
				vrr_info->nr_holding_pages--;
			else
				vrr_info->nr_private_pages--;

			cow_page->state = RR_COW_STATE_ROLLBACK;
			list_move_tail(&cow_page->link, rollback_head);
			vrr_info->nr_rollback_pages++;
		} else {
			RR_ERR("error: gfn=0x%lx in dirty_bitmap but not in "
			       "cow pages", *pgfn);
		}
	}

	re_bitmap_for_each_bit(pgfn, tmp, vrr_info->private_cb) {
		cow_page = rr_hash_find(cow_hash, *pgfn);
		if (cow_page) {
			if (cow_page->state != RR_COW_STATE_ROLLBACK) {
				if (cow_page->state == RR_COW_STATE_PRIVATE)
					vrr_info->nr_private_pages--;
				else
					vrr_info->nr_holding_pages--;

				rr_spte_restore(cow_page);
				kmem_cache_free(rr_priv_page_cache,
						cow_page->private_addr);
				list_del(&cow_page->link);
				hlist_del(&cow_page->hlink);
				kmem_cache_free(rr_cow_page_cache, cow_page);
			}
		}
	}
	RR_ASSERT(list_empty(&vrr_info->private_pages));
}

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
	struct rr_vcpu_info *vrr_info = &vcpu->rr_info;
	struct list_head *head = &vrr_info->private_pages;
	struct list_head *rollback_head = &vrr_info->rollback_pages;
	int diff = re_bitmap_size(vrr_info->private_cb) +
		   re_bitmap_size(&vrr_info->dirty_bitmap) -
		   vrr_info->nr_holding_pages - vrr_info->nr_private_pages;

	if (diff <= 0) {
		rr_rollback_cow_pages_by_bitmap(vrr_info);
		return;
	}

	rr_rollback_holding_pages_by_list(vrr_info);

	/* Traverse the private_pages */
	list_for_each_entry_safe(private_page, temp, head, link)
	{
#ifdef RR_ROLLBACK_PAGES
		/* We do nothing here but keep these dirty pages in a
		 * list and copy the new content back before entering
		 * guest.
		 */
		private_page->state = RR_COW_STATE_ROLLBACK;
		list_move_tail(&private_page->link, rollback_head);
		vrr_info->nr_private_pages--;
		vrr_info->nr_rollback_pages++;
#else
		rr_spte_restore(private_page);
		kmem_cache_free(rr_priv_page_cache,
				private_page->private_addr);
		list_del(&private_page->link);
		hlist_del(&private_page->hlink);
		kmem_cache_free(rr_cow_page_cache, private_page);
		vrr_info->nr_private_pages--;
#endif
	}
}

/* Assume that pages committed here will never conflit with other vcpus. */
void rr_commit_again(struct kvm_vcpu *vcpu)
{
	struct kvm *kvm = vcpu->kvm;
	struct rr_kvm_info *krr_info = &kvm->rr_info;
	struct rr_vcpu_info *vrr_info = &vcpu->rr_info;
	int i;
	int online_vcpus = atomic_read(&kvm->online_vcpus);
	struct kvm_vcpu *vcpu_it;

	/* See if we really has something to commit again */
	if (vrr_info->commit_again_clean) {
		return;
	}

	down_read(&krr_info->tm_rwlock);

	mutex_lock(&krr_info->tm_lock);
	/* Spread the dirty_bitmap to other vcpus's conflict_bitmap */
	for (i = 0; i < online_vcpus; ++i) {
		vcpu_it = kvm->vcpus[i];
		if (vcpu_it == vcpu)
			continue;
		re_bitmap_or(vcpu_it->rr_info.public_cb,
			     &vrr_info->dirty_bitmap);
	}

	/* Commit memory here */
	rr_commit_memory_again(vcpu);

	mutex_unlock(&krr_info->tm_lock);

	up_read(&krr_info->tm_rwlock);

	/* We only handle dirty_bitmap here */
	re_bitmap_clear(&vrr_info->dirty_bitmap);
	RR_ASSERT(re_bitmap_empty(&vrr_info->access_bitmap));
	vrr_info->commit_again_clean = true;
	vrr_info->tlb_flush = true;
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
	struct list_head *head = &vrr_info->rollback_pages;
	u64 nr_chunk = vrr_info->nr_chunk;
	struct list_head *holding_head = &vrr_info->holding_pages;

	list_for_each_entry_safe(private_page, temp, head, link) {
		private_page->chunk_num = nr_chunk;
		rr_check_cow_page_before_access(vcpu, private_page);
		copy_page(private_page->private_addr,
			  private_page->original_addr);
		private_page->state = RR_COW_STATE_HOLDING;
		list_move_tail(&private_page->link, holding_head);
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
	struct kvm_lapic *apic = vcpu->arch.apic;
	struct list_head *head = &vrr_info->events_list;

	mutex_lock(&(vrr_info->events_list_lock));
	list_for_each_entry_safe(e, tmp, head, link) {
		apic_accept_irq_without_record(apic,
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
	RR_LOG("1 %d %lx %lx %x\n", vcpu->vcpu_id, rip, rcx, 0);
}

/* Dropping spte may miss some entries in the EPT. We try to complement the
 * access and dirty bitmap.
 */
static void rr_gen_bitmap_from_private_pages(struct kvm_vcpu *vcpu)
{
	struct rr_vcpu_info *vrr_info = &vcpu->rr_info;
	struct region_bitmap *access_bm = &vrr_info->access_bitmap;
	struct region_bitmap *dirty_bm = &vrr_info->dirty_bitmap;
	struct rr_cow_page *cow_page;
	struct list_head *head = &vrr_info->private_pages;
	gfn_t gfn;

	list_for_each_entry(cow_page, head, link) {
		gfn = cow_page->gfn;
		re_set_bit(gfn, access_bm);
		re_set_bit(gfn, dirty_bm);
	}
}

static int rr_ape_check_chunk(struct kvm_vcpu *vcpu)
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
	rr_gen_bitmap_from_private_pages(vcpu);
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

	++vrr_info->nr_chunk;
	down_read(&(krr_info->tm_rwlock));
	mutex_lock(&(krr_info->tm_lock));
	if (!re_bitmap_empty(vrr_info->public_cb)) {
		/* Detect conflict */
		if (rr_detect_conflict(&vrr_info->access_bitmap,
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

		vrr_info->nr_rollback = 0;
		rr_log_chunk(vcpu);

        //increase chunk size (preemption timer)
        vrr_info->timer_value = RR_DEFAULT_PREEMTION_TIMER_VAL;
	} else {
rollback:
		vrr_info->nr_rollback++;
		if (!vrr_info->exclusive_commit &&
		    vrr_info->nr_rollback >= RR_CONSEC_RB_TIME) {
			//do binary exponential back off
            vrr_info->timer_value /= 2;
            if (vrr_info->timer_value < RR_MINIMAL_PREEMTION_TIMER_VAL){
                vrr_info->timer_value = RR_DEFAULT_PREEMTION_TIMER_VAL;
                //exclusive commit
                if (atomic_dec_and_test(&krr_info->normal_commit)) {
				    /* Now we can enter exclusive commit state */
				    vrr_info->exclusive_commit = 1;
			    }
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
		++(vrr_info->nr_chunk_commit);
		rr_commit_memory(vcpu);
	} else {
		++(vrr_info->nr_chunk_rollback);
		rr_rollback_memory(vcpu);
	}

	rr_vcpu_set_chunk_state(vcpu, RR_CHUNK_STATE_FINISHED);

	up_read(&(krr_info->tm_rwlock));

	/* Reset bitmaps */
	re_bitmap_clear(&vrr_info->access_bitmap);
	re_bitmap_clear(&vrr_info->dirty_bitmap);
	re_bitmap_clear(vrr_info->private_cb);

	vmcs_write32(VMX_PREEMPTION_TIMER_VALUE, vrr_info->timer_value);
out:
	vrr_info->tlb_flush = true;
	return commit;
}

int rr_check_chunk(struct kvm_vcpu *vcpu)
{
	u32 exit_reason = rr_ops->get_vmx_exit_reason(vcpu);
	struct rr_vcpu_info *vrr_info = &vcpu->rr_info;
	int ret;

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
		ret = rr_ape_check_chunk(vcpu);
		if (ret == -1) {
			RR_ERR("error: vcpu=%d rr_ape_check_chunk() returns -1",
			       vcpu->vcpu_id);
		} else if (ret == 1) {
			rr_make_request(RR_REQ_COMMIT_AGAIN, vrr_info);
			rr_make_request(RR_REQ_POST_CHECK, vrr_info);
			rr_make_request(RR_REQ_CHECKPOINT, vrr_info);
			vrr_info->commit_again_clean = true;
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
		rr_spte_restore(private_page);
		kmem_cache_free(rr_priv_page_cache,
				private_page->private_addr);
		list_del(&private_page->link);
		hlist_del(&private_page->hlink);
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
		rr_spte_restore(private_page);
		kmem_cache_free(rr_priv_page_cache,
				private_page->private_addr);
		list_del(&private_page->link);
		hlist_del(&private_page->hlink);
		kmem_cache_free(rr_cow_page_cache, private_page);
		vrr_info->nr_rollback_pages--;
	}
}
#endif

struct rr_exit_reason_str {
	u32 exit_reason;
	char *str;
};

static struct rr_exit_reason_str RR_VMX_EXIT_REASONS[] = {
	{ EXIT_REASON_EXCEPTION_NMI,         "EXCEPTION_NMI" },
	{ EXIT_REASON_EXTERNAL_INTERRUPT,    "EXTERNAL_INTERRUPT" },
	{ EXIT_REASON_TRIPLE_FAULT,          "TRIPLE_FAULT" },
	{ EXIT_REASON_PENDING_INTERRUPT,     "PENDING_INTERRUPT" },
	{ EXIT_REASON_NMI_WINDOW,            "NMI_WINDOW" },
	{ EXIT_REASON_TASK_SWITCH,           "TASK_SWITCH" },
	{ EXIT_REASON_CPUID,                 "CPUID" },
	{ EXIT_REASON_HLT,                   "HLT" },
	{ EXIT_REASON_INVLPG,                "INVLPG" },
	{ EXIT_REASON_RDPMC,                 "RDPMC" },
	{ EXIT_REASON_RDTSC,                 "RDTSC" },
	{ EXIT_REASON_VMCALL,                "VMCALL" },
	{ EXIT_REASON_VMCLEAR,               "VMCLEAR" },
	{ EXIT_REASON_VMLAUNCH,              "VMLAUNCH" },
	{ EXIT_REASON_VMPTRLD,               "VMPTRLD" },
	{ EXIT_REASON_VMPTRST,               "VMPTRST" },
	{ EXIT_REASON_VMREAD,                "VMREAD" },
	{ EXIT_REASON_VMRESUME,              "VMRESUME" },
	{ EXIT_REASON_VMWRITE,               "VMWRITE" },
	{ EXIT_REASON_VMOFF,                 "VMOFF" },
	{ EXIT_REASON_VMON,                  "VMON" },
	{ EXIT_REASON_CR_ACCESS,             "CR_ACCESS" },
	{ EXIT_REASON_DR_ACCESS,             "DR_ACCESS" },
	{ EXIT_REASON_IO_INSTRUCTION,        "IO_INSTRUCTION" },
	{ EXIT_REASON_MSR_READ,              "MSR_READ" },
	{ EXIT_REASON_MSR_WRITE,             "MSR_WRITE" },
	{ EXIT_REASON_MWAIT_INSTRUCTION,     "MWAIT_INSTRUCTION" },
	{ EXIT_REASON_MONITOR_INSTRUCTION,   "MONITOR_INSTRUCTION" },
	{ EXIT_REASON_PAUSE_INSTRUCTION,     "PAUSE_INSTRUCTION" },
	{ EXIT_REASON_MCE_DURING_VMENTRY,    "MCE_DURING_VMENTRY" },
	{ EXIT_REASON_TPR_BELOW_THRESHOLD,   "TPR_BELOW_THRESHOLD" },
	{ EXIT_REASON_APIC_ACCESS,           "APIC_ACCESS" },
	{ EXIT_REASON_EPT_VIOLATION,         "EPT_VIOLATION" },
	{ EXIT_REASON_EPT_MISCONFIG,         "EPT_MISCONFIG" },
	{ EXIT_REASON_WBINVD,                "WBINVD" },
	{ EXIT_REASON_APIC_WRITE,            "APIC_WRITE" },
	{ EXIT_REASON_EOI_INDUCED,           "EOI_INDUCED" },
	{ EXIT_REASON_INVALID_STATE,         "INVALID_STATE" },
	{ EXIT_REASON_INVD,                  "INVD" },
	{ EXIT_REASON_INVPCID,               "INVPCID" },
	{ EXIT_REASON_PREEMPTION_TIMER,      "PREEMPTION_TIMER" },
	{ RR_EXIT_REASON_WRITE_FAULT,	     "WRITE_FAULT" }
};

static inline char *__rr_exit_reason_to_str(u32 exit_reason)
{
	int i;

	for (i = 0; i < RR_NR_EXIT_REASON_MAX; ++i) {
		if (RR_VMX_EXIT_REASONS[i].exit_reason == exit_reason)
			return RR_VMX_EXIT_REASONS[i].str;
	}
	return "[unknown reason]";
}

static void __rr_print_sta(struct kvm *kvm)
{
	int online_vcpus = atomic_read(&kvm->online_vcpus);
	int i;
	struct kvm_vcpu *vcpu_it;
	u64 nr_exits = 0;
	u64 temp;
	u32 exit_reason;
	u64 cal_exit_reason = 0;
	u64 nr_chunk_commit = 0;
	u64 nr_chunk_rollback = 0;
	struct rr_kvm_info *krr_info = &kvm->rr_info;
	u64 exit_time = 0;
	u64 cal_exit_time = 0;
	u64 temp_exit_time, temp_exit_counter;
	struct rr_exit_stat *exit_stat;

	RR_LOG("=== Statistics for Samsara ===\n");
	printk(KERN_INFO "=== Statistics for Samsara ===\n");
	for (i = 0; i < online_vcpus; ++i) {
		vcpu_it = kvm->vcpus[i];
		temp = vcpu_it->rr_info.nr_exits;
		nr_exits += temp;
		RR_LOG("vcpu=%d nr_exits=%lld\n", vcpu_it->vcpu_id,
		       temp);
		printk(KERN_INFO "vcpu=%d nr_exits=%lld\n", vcpu_it->vcpu_id,
		       temp);
	}
	RR_LOG("total nr_exits=%lld\n", nr_exits);
	printk(KERN_INFO "total nr_exits=%lld\n", nr_exits);

	RR_LOG(">>> Stat for exit reasons:\n");
	for (exit_reason = 0; exit_reason < RR_NR_EXIT_REASON_MAX;
	     ++exit_reason) {
		temp_exit_counter = 0;
		temp_exit_time = 0;
		for (i = 0; i < online_vcpus; ++i) {
			exit_stat = &(kvm->vcpus[i]->rr_info.exit_stat[exit_reason]);
			temp_exit_counter += exit_stat->counter;
			temp_exit_time += exit_stat->time;
		}
		if (temp_exit_counter == 0) {
			if (temp_exit_time != 0) {
				RR_ERR("error: exit_reason=%d counter=%llu "
				       "time=%llu", exit_reason,
				       temp_exit_counter, temp_exit_time);
			}
			continue;
		}

		if (exit_reason < RR_EXIT_REASON_MAX) {
			cal_exit_reason += temp_exit_counter;
			cal_exit_time += temp_exit_time;
		}

		RR_LOG("%s(#%u)=%llu time=%llu\n",
		       __rr_exit_reason_to_str(exit_reason),
		       exit_reason, temp_exit_counter, temp_exit_time);
	}
	if (cal_exit_reason != nr_exits) {
		RR_ERR("error: calculated_nr_exits=%llu != nr_exits=%llu",
		       cal_exit_reason, nr_exits);
	}

	RR_LOG(">>> Stat for chunks:\n");
	for (i = 0; i < online_vcpus; ++i) {
		vcpu_it = kvm->vcpus[i];
		temp = vcpu_it->rr_info.nr_chunk_commit;
		nr_chunk_commit += temp;
		RR_LOG("vcpu=%d nr_chunk_commit=%llu\n", vcpu_it->vcpu_id,
		       temp);
		temp = vcpu_it->rr_info.nr_chunk_rollback;
		nr_chunk_rollback += temp;
		RR_LOG("vcpu=%d nr_chunk_rollback=%llu\n", vcpu_it->vcpu_id,
		       temp);
	}
	RR_LOG("total nr_chunk_commit=%llu\n", nr_chunk_commit);
	RR_LOG("total nr_chunk_rollback=%llu\n", nr_chunk_rollback);

	RR_LOG(">>> Stat for time:\n");
	for (i = 0; i < online_vcpus; ++i) {
		vcpu_it = kvm->vcpus[i];
		temp = vcpu_it->rr_info.exit_time;
		exit_time += temp;
		RR_LOG("vcpu=%d exit_time=%llu\n", vcpu_it->vcpu_id, temp);
	}
	RR_LOG("total exit_time=%llu\n", exit_time);

	if (exit_time != cal_exit_time) {
		RR_ERR("error: calculated_exit_time=%llu != "
		       "exit_time=%llu", cal_exit_time, exit_time);
	}

	if (krr_info->enabled_time >= krr_info->disabled_time) {
		temp = (~0ULL) - krr_info->enabled_time +
		       krr_info->disabled_time;
		RR_ERR("warning: time wrapped");
	} else
		temp = krr_info->disabled_time - krr_info->enabled_time;

	RR_LOG("record_up_time=%llu (enabled=%llu disabled=%llu)\n",
	       temp, krr_info->enabled_time, krr_info->disabled_time);
}

static int __rr_ape_disable(struct kvm_vcpu *vcpu)
{
	struct rr_kvm_info *krr_info = &vcpu->kvm->rr_info;
	struct rr_vcpu_info *vrr_info = &vcpu->rr_info;
	struct rr_event *eve, *eve_tmp;

	if (vrr_info->is_master) {
		struct rr_chunk_info *chunk, *temp;

		/* Release rr_kvm_info */
		rdtscll(krr_info->disabled_time);
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
		atomic_set(&krr_info->normal_commit, 1);
		krr_info->last_record_vcpu = -1;
	}

	vrr_info->enabled = false;
	rr_clear_all_request(vrr_info);
	vrr_info->nr_rollback = 0;
	vrr_info->tlb_flush = false;

	if (vrr_info->is_master)
		__rr_print_sta(vcpu->kvm);

	/* Release events_list */
	mutex_lock(&vrr_info->events_list_lock);
	list_for_each_entry_safe(eve, eve_tmp, &vrr_info->events_list, link) {
		list_del(&eve->link);
		kmem_cache_free(rr_event_cache, eve);
	}
	mutex_unlock(&vrr_info->events_list_lock);

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

	rr_clear_hash(&vrr_info->cow_hash);

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

void rr_trace_vm_exit(struct kvm_vcpu *vcpu)
{
	rr_ops->trace_vm_exit(vcpu);
}
EXPORT_SYMBOL_GPL(rr_trace_vm_exit);
