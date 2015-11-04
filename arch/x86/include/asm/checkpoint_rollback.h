#ifndef _ASM_X86_CHECKPOINT_ROLLBACK_H
#define _ASM_X86_CHECKPOINT_ROLLBACK_H

typedef struct MSRdata{
	struct kvm_msrs info;
	struct kvm_msr_entry entries[100];
} MSRdata;

struct rsr_lapic {

	/* The highest vector set in ISR; if -1 - invalid, must scan ISR. */
	int highest_isr_cache;
	/**
	 * APIC register page.  The layout matches the register layout seen by
	 * the guest 1:1, because it is accessed by the vmx microcode.
	 * Note: Only one register, the TPR, is used by the microcode.
	 */
	char regs[KVM_APIC_REG_SIZE];
};


typedef struct CPUX86State {

	/* standard registers */
	struct kvm_regs kvm_regs;

	/* FPU state */
	struct kvm_fpu fpu;

	struct kvm_xsave xsave;

	struct kvm_xcrs xcrs;

	struct kvm_mp_state mp_state;

	/* APIC regs */
	//struct kvm_lapic_state kapic;

	//rsr-debug APIC status
	struct rsr_lapic lapic;
	//end rsr-debug

	/* Debug registers */
	struct kvm_debugregs dbgregs;

	/* segments */
	struct kvm_sregs sregs;

	struct kvm_vcpu_events vcpu_events;
	/* MSRs */
	struct MSRdata msr_data;
} CPUX86State;

int rr_do_vcpu_checkpoint(struct kvm_vcpu *vcpu);

int rr_do_vcpu_rollback(struct kvm_vcpu *vcpu);

#endif

