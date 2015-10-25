// Author:RSR Date:25/11/13

#include <linux/kvm_host.h>
#include <linux/kvm.h>
#include <linux/slab.h>
//#include <linux/gfp.h>

#include <asm/kvm_checkpoint_rollback.h>
#include <asm/processor.h>
#include <asm/kvm_para.h>
#include <asm/msr-index.h>

#include "irq.h"

//rsr-debug
#include "mmu.h"
//end rsr-debug

//#define CONFIG_RSR_CHECKPOINT_DEBUG 0

#ifdef CONFIG_RSR_CHECKPOINT_DEBUG
#include "kvm_cache_regs.h"
#endif

static inline int kvm_has_feature(unsigned int feature)
{
	if (cpuid_eax(KVM_CPUID_FEATURES) & (1UL << feature))
		return 1;
	else
		return 0;
}

static int kvm_getset_regs(struct kvm_vcpu *vcpu, CPUX86State *env, int set)
{
    struct kvm_regs *kvm_regs = &env->kvm_regs;
    int ret = -ENOMEM;
	if (!set) {
		memset(kvm_regs, 0, sizeof(struct kvm_regs));
	}
	ret = kvm_arch_vcpu_ioctl_to_make_checkpoint(vcpu, set?KVM_SET_REGS:KVM_GET_REGS, 
												 kvm_regs);
	
#ifdef CONFIG_RSR_CHECKPOINT_DEBUG
	print_record("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
	print_record("cpu_regs:\n");
	print_record("VCPU_REGS_RAX=0x%lx\n",kvm_register_read(vcpu, VCPU_REGS_RAX));
	print_record("VCPU_REGS_RBX=0x%lx\n",kvm_register_read(vcpu, VCPU_REGS_RBX));
	print_record("VCPU_REGS_RCX=0x%lx\n",kvm_register_read(vcpu, VCPU_REGS_RCX));
	print_record("VCPU_REGS_RDX=0x%lx\n",kvm_register_read(vcpu, VCPU_REGS_RDX));
	print_record("VCPU_REGS_RSI=0x%lx\n",kvm_register_read(vcpu, VCPU_REGS_RSI));
	print_record("VCPU_REGS_RDI=0x%lx\n",kvm_register_read(vcpu, VCPU_REGS_RDI));
	print_record("VCPU_REGS_RSP=0x%lx\n",kvm_register_read(vcpu, VCPU_REGS_RSP));
	print_record("VCPU_REGS_RBP=0x%lx\n",kvm_register_read(vcpu, VCPU_REGS_RBP));
#ifdef CONFIG_X86_64
	print_record("VCPU_REGS_R8=0x%lx\n",kvm_register_read(vcpu, VCPU_REGS_R8));
	print_record("VCPU_REGS_R9=0x%lx\n",kvm_register_read(vcpu, VCPU_REGS_R9));
	print_record("VCPU_REGS_R10=0x%lx\n",kvm_register_read(vcpu, VCPU_REGS_R10));
	print_record("VCPU_REGS_R11=0x%lx\n",kvm_register_read(vcpu, VCPU_REGS_R11));
	print_record("VCPU_REGS_R12=0x%lx\n",kvm_register_read(vcpu, VCPU_REGS_R12));
	print_record("VCPU_REGS_R13=0x%lx\n",kvm_register_read(vcpu, VCPU_REGS_R13));
	print_record("VCPU_REGS_R14=0x%lx\n",kvm_register_read(vcpu, VCPU_REGS_R14));
	print_record("VCPU_REGS_R15=0x%lx\n",kvm_register_read(vcpu, VCPU_REGS_R15));
#endif
	print_record("regs->rip=0x%lx\n",kvm_rip_read(vcpu));
	print_record("regs->rflags=0x%lx\n",kvm_get_rflags(vcpu));
#endif
	
	return ret;
}

static int kvm_getset_fpu(struct kvm_vcpu *vcpu, CPUX86State *env, int set)
{
    struct kvm_fpu *fpu = &env->fpu;
    int ret = -ENOMEM;

#ifdef CONFIG_RSR_CHECKPOINT_DEBUG
	struct i387_fxsave_struct *fxsave =	&vcpu->arch.guest_fpu.state->fxsave;
	int i;
#endif
	
	if (!set){
		memset(fpu, 0, sizeof(struct kvm_fpu));
	}
	ret = kvm_arch_vcpu_ioctl_to_make_checkpoint(vcpu, set?KVM_SET_FPU:KVM_GET_FPU, fpu);

#ifdef CONFIG_RSR_CHECKPOINT_DEBUG
	print_record("\ncpu_fpu\n");
	print_record("cwd=0x%x\n",fxsave->cwd);
	print_record("swd=0x%x\n",fxsave->swd);
	print_record("twd=0x%x\n",fxsave->twd);
	print_record("fop=0x%x\n",fxsave->fop);
	
	print_record("rip=0x%llx\n",fxsave->rip);
	print_record("rdp=0x%llx\n",fxsave->rdp);
	
	print_record("mxcsr=0x%lx\n",fxsave->mxcsr);
	print_record("mxcsr_mask=0x%lx\n",fxsave->mxcsr_mask);
	
	for (i = 0; i < 32; i++)
		if (0 != fxsave->st_space[i])
			print_record("st_space[%d]=0x%lx  ", i, fxsave->st_space[i]);
	print_record("\n");
	for (i = 0; i < 64; i++)
		if (0 != fxsave->xmm_space[i])
			print_record("xmm_space[%d]=0x%lx  ", i, fxsave->xmm_space[i]);
	print_record("\n");

#endif

	return ret;
}

static int kvm_getset_xsave(struct kvm_vcpu *vcpu, CPUX86State *env, int set)
{
    struct kvm_xsave *xsave = &env->xsave;
    int ret = -ENOMEM;

#ifdef CONFIG_RSR_CHECKPOINT_DEBUG
	struct i387_fxsave_struct *fxsave =	&vcpu->arch.guest_fpu.state->fxsave;
	int i;
#endif

    if (!cpu_has_xsave) {
        return kvm_getset_fpu(vcpu, env, set);
    }
	if (!set) {
		memset(xsave, 0, sizeof(struct kvm_xsave));
	}
	ret = kvm_arch_vcpu_ioctl_to_make_checkpoint(vcpu, set?KVM_SET_XSAVE:KVM_GET_XSAVE,
												 xsave);
#ifdef CONFIG_RSR_CHECKPOINT_DEBUG
	print_record("\ncpu_xsave\n");
	print_record("cwd=0x%x\n",fxsave->cwd);
	print_record("swd=0x%x\n",fxsave->swd);
	print_record("twd=0x%x\n",fxsave->twd);
	print_record("fop=0x%x\n",fxsave->fop);
	
	print_record("rip=0x%llx\n",fxsave->rip);
	print_record("rdp=0x%llx\n",fxsave->rdp);

	print_record("mxcsr=0x%lx\n",fxsave->mxcsr);
	print_record("mxcsr_mask=0x%lx\n",fxsave->mxcsr_mask);

	for (i = 0; i < 32; i++)
		if (0 != fxsave->st_space[i])
			print_record("st_space[%d]=0x%lx  ", i, fxsave->st_space[i]);
	print_record("\n");
	for (i = 0; i < 64; i++)
		if (0 != fxsave->xmm_space[i])
			print_record("xmm_space[%d]=0x%lx  ", i, fxsave->xmm_space[i]);
	print_record("\n");
#endif

    return ret;
}

static int kvm_getset_xcrs(struct kvm_vcpu *vcpu, CPUX86State *env, int set)
{
    struct kvm_xcrs *xcrs = &env->xcrs;

	if (!cpu_has_xsave) {
		return 0;
	}
	if (!set) {
		memset(xcrs, 0, sizeof(struct kvm_xcrs));
	}
	kvm_arch_vcpu_ioctl_to_make_checkpoint(vcpu, set?KVM_SET_XCRS:KVM_GET_XCRS, xcrs);

#ifdef CONFIG_RSR_CHECKPOINT_DEBUG
	print_record("\nvcpu_xcr:\nvcpu->arch.xcr0=0x%llx\n", vcpu->arch.xcr0);
#endif

    return 0;
}

static int kvm_getset_mp_state(struct kvm_vcpu *vcpu, CPUX86State *env, int set)
{
    struct kvm_mp_state *mp_state = &env->mp_state;
    int ret = -ENOMEM;
	if (!set) {
		memset(mp_state, 0, sizeof(struct kvm_mp_state));
	}
    ret = kvm_arch_vcpu_ioctl_to_make_checkpoint(vcpu, set?KVM_SET_MP_STATE:KVM_GET_MP_STATE,
												 mp_state);

#ifdef CONFIG_RSR_CHECKPOINT_DEBUG
	print_record("\nvcpu_mp_state:\nmp_state=%lx\n", vcpu->arch.mp_state);
#endif


	// env->halted is in the macro "CPU_COMMON", this filed shoule be filled 
	// when kvm in kernel irqchip is enabled
	/*
	//in kvm, need to change to these
	if (irqchip_in_kernel(vcpu->kvm)){

	}

	if (kvm_irqchip_in_kernel()) {
		env->halted = (mp_state.mp_state == KVM_MP_STATE_HALTED);
	}
	*/
    return ret;
}


static int kvm_getset_apic(struct kvm_vcpu *vcpu, CPUX86State *env, int set)
{
	//struct kvm_lapic_state *kapic = &env->kapic;
	//rsr-debug
	struct rsr_lapic *lapic = &env->lapic;
	//end rsr-debug
	int ret;
#ifdef CONFIG_RSR_CHECKPOINT_DEBUG
	int i;
#endif
	
	if (!set) {
		memset(lapic, 0, sizeof(struct rsr_lapic));
	}
    if (irqchip_in_kernel(vcpu->kvm)) {
		ret = kvm_arch_vcpu_ioctl_to_make_checkpoint(vcpu, set?KVM_SET_LAPIC:KVM_GET_LAPIC,
													  lapic);
#ifdef CONFIG_RSR_CHECKPOINT_DEBUG
		print_record("\ncpu_apic:\nISR:");
		for (i=0; i<8; i++){
			if ( 0 != kvm_apic_get_reg(vcpu->arch.apic, APIC_ISR+ 0x10 * i) )
				print_record("regs[%d]= 0x%x ", i, kvm_apic_get_reg(vcpu->arch.apic, APIC_ISR+ 0x10 * i));
		}
		print_record("\nIRR:");
		for (i=0; i<8; i++)
			if ( 0 != kvm_apic_get_reg(vcpu->arch.apic, APIC_IRR+ 0x10 * i) )
				print_record("regs[%d]= 0x%8x ", i, kvm_apic_get_reg(vcpu->arch.apic, APIC_IRR+ 0x10 * i));
		print_record("\napic->irr_pending=%d , ", vcpu->arch.apic->irr_pending );	


		print_record("APIC_PROCPRI=0x%x \n", kvm_apic_get_reg(vcpu->arch.apic, APIC_PROCPRI));
		print_record("APIC_TASKPRI=0x%x \n", kvm_apic_get_reg(vcpu->arch.apic, APIC_TASKPRI));

		print_record("base_address=%lu \n", vcpu->arch.apic->base_address);
		print_record("kvm_timer=%lld \n", vcpu->arch.apic->lapic_timer.period);
		print_record("divide_count=%u \n", vcpu->arch.apic->divide_count);
		print_record("isr_count=%d \n", vcpu->arch.apic->isr_count);
		print_record("highest_isr_cache=%d \n", vcpu->arch.apic->highest_isr_cache);
		print_record("vapic_addr=%llu \n",vcpu->arch.apic->vapic_addr);
		print_record("pending_events=%lu \n", vcpu->arch.apic->pending_events);
		print_record("sipi_vector=%u \n",vcpu->arch.apic->sipi_vector);
#endif		
		
		return ret;
    }
    return 0;
}

static int kvm_getset_debugregs(struct kvm_vcpu *vcpu, CPUX86State *env, int set)
{
    struct kvm_debugregs *dbgregs = &env->dbgregs;
    int ret = -ENOMEM;
#ifdef CONFIG_RSR_CHECKPOINT_DEBUG
	int i;
#endif
	

	//if you really want to check if our vcpu has these regs, use func "kvm_dev_ioctl_check_extension"
	/*
	if (!kvm_has_debugregs()) {
		return 0;
	}*/
	if (!set) {
		memset(dbgregs, 0, sizeof(struct kvm_debugregs));
	}
    ret = kvm_arch_vcpu_ioctl_to_make_checkpoint(vcpu, set?KVM_SET_DEBUGREGS:KVM_GET_DEBUGREGS,
												 dbgregs);

#ifdef CONFIG_RSR_CHECKPOINT_DEBUG
	print_record("\ndebug_regs:\nswitch_db_regs=%d \n", vcpu->arch.switch_db_regs);
	for (i = 0; i < 4; i++)
		print_record("db[%d]=0x%lx ", i, vcpu->arch.db[i]);
	print_record("\ndr6=0x%lx \n", vcpu->arch.dr6);
	print_record("dr7=0x%lx \n", vcpu->arch.dr7);
	for (i = 0; i < 4; i++)
		print_record("eff_db[%d]=0x%lx ", i, vcpu->arch.eff_db[i]);
	print_record("\nguest_debug_dr7=0x%lx \n", vcpu->arch.guest_debug_dr7);
#endif
	
    return ret;
}

static int kvm_getset_vcpu_events(struct kvm_vcpu *vcpu, CPUX86State *env, int set)
{
	struct kvm_vcpu_events *events = &env->vcpu_events;
    int ret = -ENOMEM;

	//need to check if the core kvm API support this extensions
	//if you really want to check if our vcpu has these regs, use func "kvm_dev_ioctl_check_extension"
	/*
	if (!kvm_has_vcpu_events()) {
		return 0;
	}
 	*/
	if (!set) {
		memset(events, 0, sizeof(struct kvm_vcpu_events));
	}
    ret = kvm_arch_vcpu_ioctl_to_make_checkpoint(vcpu, set?KVM_SET_VCPU_EVENTS:KVM_GET_VCPU_EVENTS,
												 events);

#ifdef CONFIG_RSR_CHECKPOINT_DEBUG
	print_record("\nvcpu_events:\nexception->pending=%d\n", vcpu->arch.exception.pending);
	print_record("exception->has_error_code=%d\n", vcpu->arch.exception.has_error_code);
	print_record("exception->reinject=%d\n", vcpu->arch.exception.reinject);
	print_record("exception->nr=%d\n", vcpu->arch.exception.nr);
	print_record("exception->error_code=%d\n", vcpu->arch.exception.error_code);
	
	print_record("interrupt->pending=%d\n", vcpu->arch.interrupt.pending);
	print_record("interrupt->soft=%d\n", vcpu->arch.interrupt.soft);
	print_record("interrupt->nr=%d\n", vcpu->arch.interrupt.nr);
	
	print_record("nmi_queued=%d\n", vcpu->arch.nmi_queued.counter);
	print_record("nmi_pending=%u\n", vcpu->arch.nmi_pending);
	print_record("nmi_pending=%d\n", vcpu->arch.nmi_injected);

	print_record("vcpu->arch.apic->sipi_vector=%lu\n", vcpu->arch.apic->sipi_vector);
	print_record("kvm_x86_ops->get_nmi_mask=%d\n", kvm_x86_ops->get_nmi_mask(vcpu));
	print_record("kvm_x86_ops->get_interrupt_shadow=%d\n", kvm_x86_ops->get_interrupt_shadow(vcpu,	KVM_X86_SHADOW_INT_MOV_SS | KVM_X86_SHADOW_INT_STI));

#endif

    return ret;
}

static int kvm_getset_sregs(struct kvm_vcpu *vcpu, CPUX86State *env, int set)
{
    struct kvm_sregs *sregs = &env->sregs;
    int ret = -ENOMEM;

#ifdef CONFIG_RSR_CHECKPOINT_DEBUG
	struct kvm_sregs sergs_debug;
	struct kvm_segment *seg;
#endif
	
	if (!set) {
		memset(sregs, 0, sizeof(struct kvm_sregs));
	}
	ret = kvm_arch_vcpu_ioctl_to_make_checkpoint(vcpu, set?KVM_SET_SREGS:KVM_GET_SREGS, sregs);

#ifdef CONFIG_RSR_CHECKPOINT_DEBUG
	kvm_arch_vcpu_ioctl_to_make_checkpoint(vcpu, KVM_GET_SREGS, &sergs_debug);

	print_record("\nvcpu_sregs:\n");
	seg = &(sergs_debug.cs);
	print_record("cs: base=0x%llx, limit=%lu, selector=%u, type=%u, present=%u, dpl=%u, db=%u, s=%u, l=%u, g=%u, avl=%u, unusable=%u\n"
				, seg->base, seg->limit, seg->selector, seg->type, seg->present, seg->dpl, seg->db, seg->s
				, seg->l, seg->g, seg->avl, seg->unusable);
	seg = &(sergs_debug.ds);
	print_record("ds: base=0x%llx, limit=%lu, selector=%u, type=%u, present=%u, dpl=%u, db=%u, s=%u, l=%u, g=%u, avl=%u, unusable=%u\n"
				, seg->base, seg->limit, seg->selector, seg->type, seg->present, seg->dpl, seg->db, seg->s
				, seg->l, seg->g, seg->avl, seg->unusable);	
	seg = &(sergs_debug.es);
	print_record("es: base=0x%llx, limit=%lu, selector=%u, type=%u, present=%u, dpl=%u, db=%u, s=%u, l=%u, g=%u, avl=%u, unusable=%u\n"
				, seg->base, seg->limit, seg->selector, seg->type, seg->present, seg->dpl, seg->db, seg->s
				, seg->l, seg->g, seg->avl, seg->unusable);	
	seg = &(sergs_debug.fs);
	print_record("fs: base=0x%llx, limit=%lu, selector=%u, type=%u, present=%u, dpl=%u, db=%u, s=%u, l=%u, g=%u, avl=%u, unusable=%u\n"
				, seg->base, seg->limit, seg->selector, seg->type, seg->present, seg->dpl, seg->db, seg->s
				, seg->l, seg->g, seg->avl, seg->unusable);	
	seg = &(sergs_debug.gs);
	print_record("gs: base=0x%llx, limit=%lu, selector=%u, type=%u, present=%u, dpl=%u, db=%u, s=%u, l=%u, g=%u, avl=%u, unusable=%u\n"
				, seg->base, seg->limit, seg->selector, seg->type, seg->present, seg->dpl, seg->db, seg->s
				, seg->l, seg->g, seg->avl, seg->unusable);		
	seg = &(sergs_debug.ss);
	print_record("ss: base=0x%llx, limit=%lu, selector=%u, type=%u, present=%u, dpl=%u, db=%u, s=%u, l=%u, g=%u, avl=%u, unusable=%u\n"
				, seg->base, seg->limit, seg->selector, seg->type, seg->present, seg->dpl, seg->db, seg->s
				, seg->l, seg->g, seg->avl, seg->unusable);	
	seg = &(sergs_debug.tr);
	print_record("tr: base=0x%llx, limit=%lu, selector=%u, type=%u, present=%u, dpl=%u, db=%u, s=%u, l=%u, g=%u, avl=%u, unusable=%u\n"
				, seg->base, seg->limit, seg->selector, seg->type, seg->present, seg->dpl, seg->db, seg->s
				, seg->l, seg->g, seg->avl, seg->unusable);	
	seg = &(sergs_debug.ldt);
	print_record("ldt: base=0x%llx, limit=%lu, selector=%u, type=%u, present=%u, dpl=%u, db=%u, s=%u, l=%u, g=%u, avl=%u, unusable=%u\n"
				, seg->base, seg->limit, seg->selector, seg->type, seg->present, seg->dpl, seg->db, seg->s
				, seg->l, seg->g, seg->avl, seg->unusable);	

	print_record("gdt: base=0x%llx, limit=%u\n", sergs_debug.gdt.base, sergs_debug.gdt.limit);
	print_record("idt: base=0x%llx, limit=%u\n", sergs_debug.idt.base, sergs_debug.idt.limit);

	print_record("cr0=0x%llx, cr2=0x%llx, cr3=0x%llx, cr4=0x%llx, cr8=0x%llx\n", sergs_debug.cr0, sergs_debug.cr2
				, sergs_debug.cr3, sergs_debug.cr4, sergs_debug.cr8);

	print_record("efer=0x%llx, apic_base=0x%llx\n", sergs_debug.efer, sergs_debug.apic_base);	

	print_record("interrupt_bitmap--1=0x%llx, 2=0x%llx, 3=0x%llx, 4=0x%llx\n", sergs_debug.interrupt_bitmap[0]
				, sergs_debug.interrupt_bitmap[1], sergs_debug.interrupt_bitmap[2], sergs_debug.interrupt_bitmap[3]);
#endif	
	
    return ret;
}

static int kvm_getset_msrs(struct kvm_vcpu *vcpu, CPUX86State *env, int set)
{
	struct MSRdata *msr_data = &env->msr_data;
	struct kvm_msr_entry *msrs = msr_data->entries;
	int ret = -ENOMEM, n = 0, i = 0;
	uint64_t mcg_cap  = 0;

#ifdef CONFIG_RSR_CHECKPOINT_DEBUG
	struct MSRdata msr_data_debug;
#endif
	
	if (!set) {
		memset(msr_data, 0, sizeof(struct MSRdata));
		
		n = 0;

		msrs[n++].index = MSR_IA32_SYSENTER_CS;
		msrs[n++].index = MSR_IA32_SYSENTER_ESP;
		msrs[n++].index = MSR_IA32_SYSENTER_EIP;
		msrs[n++].index = MSR_IA32_CR_PAT;

		//need to check if our vcpu really has these msrs ! 
		//if you really want to check this, use ioctl "KVM_GET_MSR_INDEX_LIST"
		msrs[n++].index = MSR_STAR;
		
		// we don't have this
		//msrs[n++].index = MSR_VM_HSAVE_PA;

		//emulated msrs
		msrs[n++].index = MSR_IA32_TSCDEADLINE;
		msrs[n++].index = MSR_IA32_MISC_ENABLE;

		msrs[n++].index = MSR_IA32_TSC;

#ifdef CONFIG_X86_64

		msrs[n++].index = MSR_CSTAR;
		msrs[n++].index = MSR_KERNEL_GS_BASE;

		msrs[n++].index = MSR_SYSCALL_MASK;
		msrs[n++].index = MSR_LSTAR;
		
#endif

		/*
		 * The following paravirtual MSRs have side effects on the guest or are
		 * too heavy for normal writeback. Limit them to reset or full state
		 * updates.
		 */

		//do we need to reset time?
		/*
         * KVM is yet unable to synchronize TSC values of multiple VCPUs on
         * writeback. Until this is fixed, we only write the offset to SMP
         * guests after migration, desynchronizing the VCPUs, but avoiding
         * huge jump-backs that would occur without any writeback at all.
         */

		/*same as MSR_KVM_WALL_CLOCK_NEW. Use that instead.
		  *The hypervisor is only guaranteed to update this data at the moment of MSR write.
		  *Note that although MSRs are per-CPU entities, the effect of this particular MSR is global.
		  */
		//1 rsr-debug just for debugging
		//msrs[n++].index = MSR_KVM_WALL_CLOCK_NEW;
		//same as MSR_KVM_SYSTEM_TIME_NEW. Use that instead.
		//msrs[n++].index = MSR_KVM_SYSTEM_TIME_NEW;
		if (kvm_has_feature(KVM_FEATURE_ASYNC_PF)) {
			msrs[n++].index = MSR_KVM_ASYNC_PF_EN;
		}
		if (kvm_has_feature(KVM_FEATURE_PV_EOI)) {
			msrs[n++].index = MSR_KVM_PV_EOI_EN;
		}

		mcg_cap = vcpu->arch.mcg_cap;	//need to confirm!!!

#ifdef KVM_CAP_MCE
		msrs[n++].index = MSR_IA32_MCG_STATUS;
		msrs[n++].index = MSR_IA32_MCG_CTL;
		for (i = 0; i < (mcg_cap & 0xff) * 4; i++) {
			msrs[n++].index = MSR_IA32_MC0_CTL + i;
		}
#endif

		//rsr-debug
		//BUG FIX: need to calculate the number of the msrs
		msr_data->info.nmsrs = n;
		//end rsr-debug
	}

	ret = kvm_arch_vcpu_ioctl_to_make_checkpoint(vcpu, set?KVM_SET_MSRS:KVM_GET_MSRS, msr_data);

/*
#ifdef CONFIG_RSR_CHECKPOINT_DEBUG
	print_record("\nMSR: ret=%d\n", ret);
	memset(&msr_data_debug, 0 , sizeof(MSRdata));
	for (i = 0; i < ret; i++)
		msr_data_debug.entries[i].index = msrs[i].index;
	msr_data_debug.info.nmsrs = ret;
	
	kvm_arch_vcpu_ioctl_to_make_checkpoint(vcpu, KVM_GET_MSRS, &msr_data_debug);
	for (i = 0; i < ret; i++)
		print_record("msr[%d].index=%u, data=0x%llx\n"
					, i, msr_data_debug.entries[i].index, msr_data_debug.entries[i].data);

#endif
*/

    return 0;
}

int kvm_arch_getset_registers(struct kvm_vcpu *vcpu, int set)
{
	int ret;
	CPUX86State *env = &(vcpu->vcpu_checkpoint);

	ret = kvm_getset_regs(vcpu, env, set);
    if (ret < 0) {
        return ret;
    }
	ret = kvm_getset_xsave(vcpu, env, set);
    if (ret < 0) {
        return ret;
    }
    ret = kvm_getset_xcrs(vcpu, env, set);
    if (ret < 0) {
        return ret;
    }
	ret = kvm_getset_sregs(vcpu, env, set);
    if (ret < 0) {
        return ret;
    }

	//rsr-debug
	//set_sregs lead to destroy mmu which will be used in set_msrs, so reload it before set_msrs
	ret = kvm_mmu_reload(vcpu);					// Load VM memory page table
	if (unlikely(ret)) {
		printk(KERN_DEBUG "tamlok: Fail to reload mmu\n");
		return -1;
	}
	//end rsr-debug
	
	ret = kvm_getset_msrs(vcpu, env, set);
    if (ret < 0) {
        return ret;
    }
	ret = kvm_getset_mp_state(vcpu, env, set);
    if (ret < 0) {
        return ret;
    }
	ret = kvm_getset_apic(vcpu, env, set);
	if (ret < 0) {
		return ret;
	}
	ret = kvm_getset_vcpu_events(vcpu, env, set);
	if (ret < 0) {
		return ret;
	}
	ret = kvm_getset_debugregs(vcpu, env, set);
	if (ret < 0) {
		return ret;
	}

	//print_vcpu_status_info_for_debugging(env);

	return 0;
}

void print_vcpu_status_info_for_debugging(CPUX86State *env)
{
	int i = 0, j = 0;
	struct kvm_regs *kvm_regs = &env->kvm_regs;
	struct kvm_fpu *fpu = &env->fpu;

	printk("------------------standard registers-----------------\n");
	printk("rax: %llx\n", kvm_regs->rax);
	printk("rbx: %llx\n", kvm_regs->rbx);
	printk("rcx: %llx\n", kvm_regs->rcx);
	printk("rdx: %llx\n", kvm_regs->rdx);
	printk("rsi: %llx\n", kvm_regs->rsi);
	printk("rdi: %llx\n", kvm_regs->rdi);
	printk("rsp: %llx\n", kvm_regs->rsp);
	printk("rbp: %llx\n", kvm_regs->rbp);
	
	printk("r8: %llx\n", kvm_regs->r8);
	printk("r9: %llx\n", kvm_regs->r9);
	printk("r10: %llx\n", kvm_regs->r10);
	printk("r11: %llx\n", kvm_regs->r11);
	printk("r12: %llx\n", kvm_regs->r12);
	printk("r13: %llx\n", kvm_regs->r13);
	printk("r14: %llx\n", kvm_regs->r14);
	printk("r15: %llx\n", kvm_regs->r15);
	printk("rip: %llx\n", kvm_regs->rip);
	printk("rflags: %llx\n", kvm_regs->rflags);

	printk("----------------------FPU state---------------------\n");
	for (i=0; i<8; i++) {
		for(j=0; j<16; j++){
			printk("fpr[%d][%d]=0x%x ", i, j, fpu->fpr[i][j]);
		}
		printk("\n");
	}
	printk("fcw: 0x%x\n", fpu->fcw);
	printk("fsw: 0x%x\n", fpu->fsw);
	printk("ftwx: 0x%x\n", fpu->ftwx);
	printk("pad1: 0x%x\n", fpu->pad1);
	printk("last_opcode: 0x%x\n", fpu->last_opcode);
	printk("last_ip: 0x%llx\n", fpu->last_ip);	
	printk("last_dp: 0x%llx\n", fpu->last_dp);
	for (i=0; i<16; i++) {
		for(j=0; j<16; j++){
			printk("xmm[%d][%d]=0x%x ", i, j, fpu->xmm[i][j]);
		}
		printk("\n");
	}	
	printk("mxcsr: 0x%x\n", fpu->mxcsr);
	printk("pad2: 0x%x\n", fpu->pad2);	

	printk("------------------------XSAVE---------------------\n");
	for(j=0; j<1024; j++){
		printk("region[%d]=0x%x ", j, env->xsave.region[i]);
	}
	printk("\n");
	
}

int vcpu_checkpoint(struct kvm_vcpu *vcpu)
{
	int ret = kvm_arch_getset_registers(vcpu, 0);

	//printk( "Make checkpoint\n" );

	if ( ret < 0 ){
		printk( "Some Error Occured During Macking Checkpoint!\n" );
		return ret;
	}
	//print_vcpu_status_info_for_debugging(&vcpu->vcpu_checkpoint);
	return 0;
}
EXPORT_SYMBOL_GPL(vcpu_checkpoint);

int vcpu_rollback(struct kvm_vcpu *vcpu)
{
	int ret = kvm_arch_getset_registers(vcpu, 1);

	//printk( "Roll back\n" );

	if ( ret < 0 ){
		printk( "Some Error Occured During Rolling Back!\n" );
		return ret;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(vcpu_rollback);
