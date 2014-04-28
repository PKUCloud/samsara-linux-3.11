//Author:RSR Date:9/3/14

#ifndef ARCH_X86_KVM_CHECKPOINT_H
#define ARCH_X86_KVM_CHECKPOINT_H

typedef struct MSRdata{
	struct kvm_msrs info;
	struct kvm_msr_entry entries[100];	
} MSRdata;

typedef struct CPUX86State {

	/* standard registers */
	struct kvm_regs kvm_regs;
	
	/* FPU state */
	struct kvm_fpu fpu;
	
	struct kvm_xsave xsave;
	
	struct kvm_xcrs xcrs;
	
	struct kvm_mp_state mp_state;
	
	/* APIC state */
	struct kvm_lapic_state kapic;
	
	/* Debug registers */
	struct kvm_debugregs dbgregs;
	
	/* segments */
	struct kvm_sregs sregs;
	
	struct kvm_vcpu_events vcpu_events;
	/* MSRs */
	struct MSRdata msr_data;
	
} CPUX86State;

int make_vcpu_checkpoint(struct kvm_vcpu *vcpu);

int vcpu_rollback(struct kvm_vcpu *vcpu);

#endif

