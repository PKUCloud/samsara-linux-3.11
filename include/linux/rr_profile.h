#ifndef __RR_PROFILE_H
#define __RR_PROFILE_H

// 2G mem is 2G/4K=512K
// 500M mem is 128K
#define TM_BITMAP_SIZE 1024*1024

#define RR_CONSEC_RB_TIME 3

/* Early rollback and early check is exclusive */
//#define RR_EARLY_ROLLBACK
#define RR_EARLY_CHECK

/* If defined, we use the vcpu.arch.holding_pages to hold a list of pages that
 * have been COW. We will not withdraw the write permission and free the private
 * pages until we have to.
 */
#define RR_HOLDING_PAGES
/* Maximum length of vcpu.arch.holding_pages list */
#define RR_HOLDING_PAGES_MAXM        512
#define RR_HOLDING_PAGES_TARGET_NR   256

/* If defined, we use a separate list to hold pages need to rollback and before
 * entering guest, we copy the new content of those pages.
 * BUG: If kvm read/write guest pages after we rollback while other vcpus haven't
 * finished commit yet, we may read old contents. This bug is introduced in the
 * commit adding kvm.chunk_list.
 */
#define RR_ROLLBACK_PAGES

#endif
