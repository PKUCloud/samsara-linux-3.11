//Author:RSR Date:9/3/14

#ifndef ARCH_X86_KVM_CHECKPOINT_H
#define ARCH_X86_KVM_CHECKPOINT_H

#define CPU_NB_REGS64 16
#define CPU_NB_REGS32 8

#ifdef CONFIG_X86_64
#define CPU_NB_REGS CPU_NB_REGS64
#define TARGET_LONG_SIZE 8
#define TARGET_LONG_ALIGNMENT 8
#else
#define CPU_NB_REGS CPU_NB_REGS32
#define TARGET_LONG_SIZE 4
#define TARGET_LONG_ALIGNMENT 4

#endif

#define MCE_BANKS_DEF	10

#define	ENOMEM		12	/* Out of Memory */

#define KVM_CPUID_FEATURES	0x40000001

#define KVM_FEATURE_CLOCKSOURCE2        3
#define KVM_FEATURE_ASYNC_PF		4
#define KVM_FEATURE_STEAL_TIME		5
#define KVM_FEATURE_PV_EOI		6

#define MSR_IA32_APICBASE_BSP           (1<<8)
#define MSR_IA32_APICBASE_ENABLE        (1<<11)
#define MSR_IA32_APICBASE_BASE          (0xfffff<<12)

#define MSR_MTRRcap_VCNT		8
#define MSR_MTRRcap_FIXRANGE_SUPPORT	(1 << 8)
#define MSR_MTRRcap_WC_SUPPORTED	(1 << 10)

#define MSR_MCG_CAP                     0x179
#define MSR_MCG_STATUS                  0x17a
#define MSR_MCG_CTL                     0x17b

/* Indicates good rep/movs microcode on some processors: */
#define MSR_IA32_MISC_ENABLE_DEFAULT    1

#define MSR_MTRRphysBase(reg)		(0x200 + 2 * (reg))
#define MSR_MTRRphysMask(reg)		(0x200 + 2 * (reg) + 1)

#define MSR_PAT                         0x277

#define MSR_MC0_CTL			0x400
#define MSR_MC0_STATUS			0x401
#define MSR_MC0_ADDR			0x402
#define MSR_MC0_MISC			0x403

#define MSR_EFER                        0xc0000080

#define MSR_EFER_SCE   (1 << 0)
#define MSR_EFER_LME   (1 << 8)
#define MSR_EFER_LMA   (1 << 10)
#define MSR_EFER_NXE   (1 << 11)
#define MSR_EFER_SVME  (1 << 12)
#define MSR_EFER_FFXSR (1 << 14)

#define MSR_STAR                        0xc0000081
#define MSR_LSTAR                       0xc0000082
#define MSR_CSTAR                       0xc0000083
#define MSR_FMASK                       0xc0000084
#define MSR_FSBASE                      0xc0000100
#define MSR_GSBASE                      0xc0000101
#define MSR_KERNELGSBASE                0xc0000102
#define MSR_TSC_AUX                     0xc0000103

#define MSR_VM_HSAVE_PA                 0xc0010117


/* target_ulong is the type of a virtual address */
#if TARGET_LONG_SIZE == 4
typedef uint32_t target_ulong __attribute__((aligned(TARGET_LONG_ALIGNMENT)));

#elif TARGET_LONG_SIZE == 8
typedef uint64_t target_ulong __attribute__((aligned(TARGET_LONG_ALIGNMENT)));

#endif

typedef uint16_t float16;
typedef uint32_t float32;
typedef uint64_t float64;
typedef uint8_t flag;

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

