// Author:RSR Date:25/11/13

#include <linux/kvm_host.h>
#include <linux/kvm.h>
#include <linux/slab.h>
//#include <linux/gfp.h>

#include <asm/kvm_checkpoint_rollback.h>
#include <asm/processor.h>

#include "irq.h"

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
	return ret;
}

static int kvm_getset_fpu(struct kvm_vcpu *vcpu, CPUX86State *env, int set)
{
    struct kvm_fpu *fpu = &env->fpu;
    int ret = -ENOMEM;
	if (!set){
		memset(fpu, 0, sizeof(struct kvm_fpu));
	}
	ret = kvm_arch_vcpu_ioctl_to_make_checkpoint(vcpu, set?KVM_SET_FPU:KVM_GET_FPU, fpu);
    return ret;
}

static int kvm_getset_xsave(struct kvm_vcpu *vcpu, CPUX86State *env, int set)
{
    struct kvm_xsave *xsave = &env->xsave;
    int ret = -ENOMEM;

    if (!cpu_has_xsave) {
        return kvm_getset_fpu(vcpu, env, set);
    }
	if (!set) {
		memset(xsave, 0, sizeof(struct kvm_xsave));
	}
	ret = kvm_arch_vcpu_ioctl_to_make_checkpoint(vcpu, set?KVM_SET_XSAVE:KVM_GET_XSAVE,
												 xsave);
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

//2 Do we really need to record the apic information?
static int kvm_getset_apic(struct kvm_vcpu *vcpu, CPUX86State *env, int set)
{
	struct kvm_lapic_state *kapic = &env->kapic;
	if (!set) {
		memset(kapic, 0, sizeof(struct kvm_lapic_state));
	}
    if (irqchip_in_kernel(vcpu->kvm)) {
		return kvm_arch_vcpu_ioctl_to_make_checkpoint(vcpu, set?KVM_SET_LAPIC:KVM_GET_LAPIC,
													  kapic);
    }
    return 0;
}

static int kvm_getset_debugregs(struct kvm_vcpu *vcpu, CPUX86State *env, int set)
{
    struct kvm_debugregs *dbgregs = &env->dbgregs;
    int ret = -ENOMEM;

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
    return ret;
}

static int kvm_getset_sregs(struct kvm_vcpu *vcpu, CPUX86State *env, int set)
{
    struct kvm_sregs *sregs = &env->sregs;
    int ret = -ENOMEM;
	
	if (!set) {
		memset(sregs, 0, sizeof(struct kvm_sregs));
	}
	ret = kvm_arch_vcpu_ioctl_to_make_checkpoint(vcpu, set?KVM_SET_SREGS:KVM_GET_SREGS, sregs);
    return ret;
}

static int kvm_getset_msrs(struct kvm_vcpu *vcpu, CPUX86State *env, int set)
{
	struct MSRdata *msr_data = &env->msr_data;
	struct kvm_msr_entry *msrs = msr_data->entries;
	int ret = -ENOMEM, n = 0, i = 0;
	uint64_t mcg_cap  = 0;
	
	if (!set) {
		memset(msr_data, 0, sizeof(struct MSRdata));
		
		n = 0;
		msrs[n++].index = MSR_IA32_SYSENTER_CS;
		msrs[n++].index = MSR_IA32_SYSENTER_ESP;
		msrs[n++].index = MSR_IA32_SYSENTER_EIP;
		msrs[n++].index = MSR_PAT;

		//need to check if our vcpu really has these msrs ! 
		//if you really want to check this, use ioctl "KVM_GET_MSR_INDEX_LIST"
		msrs[n++].index = MSR_STAR;
		msrs[n++].index = MSR_VM_HSAVE_PA;

		//emulated msrs
		msrs[n++].index = MSR_IA32_TSCDEADLINE;
		msrs[n++].index = MSR_IA32_MISC_ENABLE;

		//do we need to record timestamp?
		/*
		if (!env->tsc_valid) {
			msrs[n++].index = MSR_IA32_TSC;
			env->tsc_valid = !runstate_is_running();
		}
		*/

#ifdef CONFIG_X86_64

		msrs[n++].index = MSR_CSTAR;
		msrs[n++].index = MSR_KERNELGSBASE;
		msrs[n++].index = MSR_FMASK;
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

		msrs[n++].index = MSR_KVM_SYSTEM_TIME;
		msrs[n++].index = MSR_KVM_WALL_CLOCK;
		if (kvm_has_feature(KVM_FEATURE_ASYNC_PF)) {
			msrs[n++].index = MSR_KVM_ASYNC_PF_EN;
		}
		if (kvm_has_feature(KVM_FEATURE_PV_EOI)) {
			msrs[n++].index = MSR_KVM_PV_EOI_EN;
		}

		mcg_cap = vcpu->arch.mcg_cap;	//need to confirm!!!

#ifdef KVM_CAP_MCE
		msrs[n++].index = MSR_MCG_STATUS;
		msrs[n++].index = MSR_MCG_CTL;
		for (i = 0; i < (mcg_cap & 0xff) * 4; i++) {
			msrs[n++].index = MSR_MC0_CTL + i;
		}
#endif
	}

	//4 All parameters are kernel addresses, so use __msr_io
	ret = kvm_arch_vcpu_ioctl_to_make_checkpoint(vcpu, set?KVM_SET_MSRS:KVM_GET_MSRS, msr_data);
	//ret = __msr_io(vcpu, &msr_data, kvm_get_msr, 1);

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

	printk("------------------standard registers-----------------\n");
	struct kvm_regs *kvm_regs = &env->kvm_regs;
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
	struct kvm_fpu *fpu = &env->fpu;
	for (i=0; i<8; i++) {
		for(j=0; j<16; j++){
			printk("fpr[%d][%d]=%llx ", i, j, fpu->fpr[i][j]);
		}
		printk("\n");
	}
	printk("fcw: %llx\n", fpu->fcw);
	printk("fsw: %llx\n", fpu->fsw);
	printk("ftwx: %llx\n", fpu->ftwx);
	printk("pad1: %llx\n", fpu->pad1);
	printk("last_opcode: %llx\n", fpu->last_opcode);
	printk("last_ip: %llx\n", fpu->last_ip);	
	printk("last_dp: %llx\n", fpu->last_dp);
	for (i=0; i<16; i++) {
		for(j=0; j<16; j++){
			printk("xmm[%d][%d]=%llx ", i, j, fpu->xmm[i][j]);
		}
		printk("\n");
	}	
	printk("mxcsr: %llx\n", fpu->mxcsr);
	printk("pad2: %llx\n", fpu->pad2);	

	printk("------------------------XSAVE---------------------\n");
	for(j=0; j<1024; j++){
		printk("region[%d]=%llx ", j, env->xsave.region[i]);
	}
	printk("\n");
	
}

int make_vcpu_checkpoint(struct kvm_vcpu *vcpu)
{
	printk( "Make checkpoint\n" );

	int ret = kvm_arch_getset_registers(vcpu, 0);
	if ( ret < 0 ){
		printk( "Some Error Occured During Macking Checkpoint!\n" );
		return ret;
	}
	//print_vcpu_status_info_for_debugging(&vcpu->vcpu_checkpoint);
	return 0;
}
EXPORT_SYMBOL_GPL(make_vcpu_checkpoint);

int vcpu_rollback(struct kvm_vcpu *vcpu)
{
	printk( "Roll back\n" );

	int ret = kvm_arch_getset_registers(vcpu, 1);
	if ( ret < 0 ){
		printk( "Some Error Occured During Rolling Back!\n" );
		return ret;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(vcpu_rollback);
