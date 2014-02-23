/*
* mmap.c  -- memory mapping for the logger module
*/
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/errno.h>
#include <asm/pgtable.h>
#include <linux/fs.h>

#include <linux/slab.h>

#include "logger.h"


extern struct kmem_cache *data_cache;
extern struct kmem_cache *quantum_cache;
extern int logger_quantum;

/*
*open and close: keep track of how many times the device is mapped
* maybe will do some cleanup
*/

void logger_vma_open(struct vm_area_struct *vma)
{
	struct logger_dev *dev = vma->vm_private_data;

	spin_lock(&dev->dev_lock);
	++(dev->vmas);
	spin_unlock(&dev->dev_lock);

	//printk(KERN_NOTICE "logger_vma_open()\n");
	//printk(KERN_NOTICE "logger_vma_open():start:%lx, end:%lx, vmas:%d\n", vma->vm_start, vma->vm_end, dev->vmas);
}

void logger_vma_close(struct vm_area_struct *vma)
{
	struct logger_dev *dev = vma->vm_private_data;
	struct logger_quantum *ptr;

	--(dev->vmas);

	//delete the data has been mapped before
	if(dev->vmas == 0 && dev->head) {
		spin_lock(&dev->dev_lock);
		ptr = dev->head;
		if(ptr->next) {
			dev->head = ptr->next;
		}else {
			dev->head = dev->tail = NULL;
			dev->str = dev->end = NULL;
		}
		kmem_cache_free(data_cache, ptr->data);
		kmem_cache_free(quantum_cache, ptr);

		dev->size -= logger_quantum;

		assert(dev->size >= 0);

		spin_unlock(&dev->dev_lock);
	}

	//printk(KERN_NOTICE "logger_vma_close()\n");

	//printk(KERN_NOTICE "logger_vma_close():start:%lx, end:%lx, vmas:%d\n", vma->vm_start, vma->vm_end, dev->vmas);
}

/*
*the nopage method has been replaced by fault method. It retrieves the
*page required from the device and returns
*it to the user. The count for the page must be incremented,
*because it is automatically decremented at page unmap.
*Actually we just map an intact page, and always the first page
*/
int logger_vma_fault(struct vm_area_struct *vma,
	struct vm_fault *vmf)
{
	unsigned long offset;
	struct logger_dev *dev = vma->vm_private_data;
	struct logger_quantum *ptr;
	struct page *page;
	void *pageptr = NULL;

	//printk(KERN_NOTICE "logger_vma_fault()\n");

	spin_lock(&dev->dev_lock);
	offset = (vmf->pgoff << PAGE_SHIFT) + (vma->vm_pgoff << PAGE_SHIFT);
	if(offset >= dev->size) goto err;   //out of range

	offset >>= PAGE_SHIFT;     // the number of pages

	//printk(KERN_NOTICE "logger_vma_fault():vmf->pgoff:%lud,start:%lx,pgoff:%lu,offset:%lu\n",
	//	vmf->pgoff, vma->vm_start, vma->vm_pgoff, offset);

	for(ptr = dev->head; ptr && offset;) {
		ptr = ptr->next;
		--offset;
	}
	//if(ptr) pageptr = ptr->data;
	if(ptr) {
		/*
		if(ptr == dev->tail) {
			//only one page left
			//See if it is intact
			if(dev->size == logger_quantum) {
				pageptr = ptr->data;
			}else {
				printk(KERN_NOTICE "Not an intact page");
				goto err;
			}
		}else pageptr = ptr->data;
		*/
		pageptr = ptr->data;
	}

	if(!pageptr) goto err;    //end of file
	page = virt_to_page(pageptr);

	assert(page != NULL);

	if(!page) {
		goto err;
	}

	//increment the count
	get_page(page);
	vmf->page = page;

	spin_unlock(&dev->dev_lock);
	return 0;

err:
	spin_unlock(&dev->dev_lock);
	return VM_FAULT_SIGBUS;
}




struct vm_operations_struct logger_vm_ops = {
	.open = logger_vma_open,
	.close = logger_vma_close,
	.fault = logger_vma_fault,
};


int logger_mmap(struct file *filp, struct vm_area_struct *vma)
{
	/* don't do anything here: "nopage" will set up page table entried*/
	struct logger_dev *dev = (struct logger_dev *)filp->private_data;
	struct logger_quantum *ptr;

	vma->vm_ops = &logger_vm_ops;
	//vma->vm_flags |= (VM_DONTEXPAND | VM_DONTDUMP);
	//vma->vm_flags |= VM_RESERVED;
	vma->vm_private_data = filp->private_data;

	//no page or only an incomplete page
	spin_lock(&dev->dev_lock);
	ptr = dev->head;
	if(dev->size < logger_quantum) {
		//printk(KERN_NOTICE "logger_mmap(): return -1, ptr:%ld, size:%ld\n", (long)ptr, dev->size);
		//printk(KERN_NOTICE "logger_mmap(): size=%ld fail\n", dev->size);
#ifdef BLOCK_VER
		while(dev->size < logger_quantum) {
			spin_unlock(&dev->dev_lock);
			if(filp->f_flags & O_NONBLOCK)
				return -EAGAIN;
			//printk(KERN_NOTICE "%s mmap(): go to sleep\n", current->comm);
			if(wait_event_interruptible(dev->queue, (dev->size >= logger_quantum)))
				return -ERESTARTSYS;
			spin_lock(&dev->dev_lock);
		}
		goto out;

#endif
		goto err;
	}
	

out:
	assert((ptr != dev->tail) || (dev->end == dev->str) );
	//printk(KERN_NOTICE "ptr==dev->tail:%d dev->end - dev->str = %ld\n", (int)(ptr==dev->tail), dev->end - dev->str);
	spin_unlock(&dev->dev_lock);
	logger_vma_open(vma);
	//printk(KERN_NOTICE "logger_mmap():start:%lx, end:%lx\n", vma->vm_start, vma->vm_end);
	return 0;


err:
	spin_unlock(&dev->dev_lock);
	return -ENODEV;
}
