/*
 * Implementation of system call of hw5
 */
#include <linux/syscalls.h>
#include <linux/sched.h>
#include <linux/mm_types.h>
#include <linux/slab.h>
#include <asm/uaccess.h>

#define __DEBUG_HW5__

#ifdef __DEBUG_HW5__
	#define log		printk
#else
	#define log(...) \
		do {} while (0)
#endif

#define M_PAGE_SIZE	(4096)
#define M_ENTRIES_PGD	(1536)
#define M_TOTAL_PTE_SZ	(M_ENTRIES_PGD * M_PAGE_SIZE)
#define	M_MEM_RANGE_PER_PTE	(4096*512)

static int do_remap_single_page(
	struct vm_area_struct *vma,
	unsigned long *addr,
	struct page *pg,
	pgprot_t prot)
{
	int retval = 0;
	unsigned long pfn = page_to_pfn(pg);

	/* do free this thing */
	atomic_inc(&(pg->_count));

	/* no map at testing phase */
	log("remap pfn: %lu to %lu\n", pfn, *addr);

	/* referenced from piazza 508 */
	retval = remap_pfn_range(
			vma, *addr, pfn,
			M_PAGE_SIZE, PAGE_READONLY);

	if (retval == 0)
		*addr += M_PAGE_SIZE;
	else
		log("ERROR: failed to remap @ 0x%08lx\n", *addr);

	return retval;
}

static void print_config(void)
{
#ifdef __DEBUG_HW5__
	unsigned long tmp = 0;

	tmp = PTRS_PER_PGD;
	log("PTRS_PER_PGD = %lu\n", tmp);

	tmp = USER_PTRS_PER_PGD;
	log("USER_PTRS_PER_PGD = %lu\n", tmp);

	tmp = TASK_SIZE;
	log("TASK_SIZE = %lu\n", tmp);

	tmp = PTRS_PER_PUD;
	log("PTRS_PER_PUD = %lu\n", tmp);

	tmp = PTRS_PER_PMD;
	log("PTRS_PER_PMD = %lu\n", tmp);
#endif
}

/*
 * Map a target process's page table into address space of the current process.
 *
 * After successfully completing this call, addr will contain the
 * page tables of the target process. To make it efficient for referencing
 * the re-mapped page tables in user space, your syscall is asked to build
 * a fake pgd table. The fake pgd will be indexed by pgd_index(VA) (i.e. index
 * for page directory for a given virtual address VA)
 *
 * @pid: pid of the target process you want to investigate, if pid == -1,
 * you should dump the current process's page tables
 * @fake_pgd: base address of the fake pgd table
 * @ addr: base address in the user space that the page tables should map to
 */
SYSCALL_DEFINE3(
	expose_page_table,
	pid_t, pid,			/* the pid you want to see */
	unsigned long, fake_pgd,	/* the fake pgd address */
	unsigned long, addr)		/* the address for PTEs */
{
	/* local vars */
	long retval = 0;
	struct task_struct *task = NULL;
	struct mm_struct *mm_cur = NULL, *mm_tgt = NULL;
	pgd_t *pgd = NULL;
	unsigned long tmp = 0, *fpgd_idx = NULL, *fpgd = NULL;
	unsigned long c_fpgd = 0;
	pgprot_t prot;
	struct vm_area_struct *vma = NULL;
	unsigned long vaddr = 0;
	unsigned long vad = 0;

	log("expose_page_table: pid = %d, fake_pgd = 0x%08x, addr = 0x%08x\n",
			pid,
			(unsigned int)fake_pgd,
			(unsigned int)addr);

	/* a function allows you to see the world */
	print_config();

	/* check input error */
	if (pid < -1 || fake_pgd == 0 || addr == 0)
		return -EINVAL;

	/* 4K alignment is much better */
	if (addr & 0x00000fff) {
		log("user assigned addr is not 4k-aligned.\n");
		return -EINVAL;
	}

	/* check input size */
	/* The size of fake_pgd should be 2048 * 0.75 * 4 */
	if (!access_ok(
		VERIFY_WRITE,
		(void *)fake_pgd,
		M_ENTRIES_PGD * sizeof(unsigned long))) {

		log("user fake pgd is insufficient.\n");
		return -EFAULT;
	}

	/* the remapping addr shall be sufficient - 1536 * 4k */
	if (!access_ok(
		VERIFY_WRITE,
		(void *)addr,
		M_ENTRIES_PGD * M_PAGE_SIZE)) {

		log("Invalid access (addr) right.\n");
		return -EFAULT;
	}

	/* get current task struct */
	if (pid == -1)
		task = current;
	else
		task = find_task_by_vpid(pid);

	if (!task) {
		log("[ERROR] task %d not found.\n", pid);
		return -EINVAL;
	}

	/*
	 * get mm of the target task
	 * After mm successfully got by get_task_mm, mmput should be
	 * invoked when the operation finishes
	 */
	mm_tgt = get_task_mm(task);

	/*
	 * Kernel thread doesn't have mm.
	 * Return error under this circumstance?
	 */
	if (!mm_tgt) {
		log("[ERROR] mm not found - trying kernel thread?\n");
		return -EFAULT;
	}

	mm_cur = get_task_mm(current);
	if (!mm_cur) {
		log("[ERROR] Current no mm?!\n");
		mmput(mm_tgt);
		return -EFAULT;
	}

	/* get pgd and translate into fake pgd
	 * traverse pgd, get pte, and construct fake_pgd
	 * for each pte
	 *  - map into user affresses
	 *  - update fake pgd
	 */
	pgd = mm_tgt->pgd;

	/* allocate a kernel space to store the pgd temporarily */
	fpgd = kmalloc(sizeof(unsigned long) * USER_PTRS_PER_PGD, GFP_KERNEL);

	if (fpgd == NULL) {
		mmput(mm_tgt);
		mmput(mm_cur);
		return -ENOMEM;
	}

	fpgd_idx = (unsigned long *)fpgd;

	/* hold the mmap_sem to process vma info */
	down_write(&mm_cur->mmap_sem);

	vma = find_vma(mm_cur, addr);
	if (vma == NULL) {
		log("ERROR: no vma is found.\n");
		up_write(&mm_cur->mmap_sem);
		kfree(fpgd);
		mmput(mm_tgt);
		mmput(mm_cur);
		return -EINVAL;
	} else if (vma->vm_mm != mm_cur) {
		log("ERROR: address from different mm??\n");
		up_write(&mm_cur->mmap_sem);
		kfree(fpgd);
		mmput(mm_tgt);
		mmput(mm_cur);
		return -EINVAL;
	}

	/* Note: end - addr is the thing we should check */
	if ((vma->vm_end - addr) < M_TOTAL_PTE_SZ) {
		log("no space in vma: 0x%08lx, 0x%08lx (%lu)(%08lx)\n",
			vma->vm_start,
			vma->vm_end,
			vma->vm_end-vma->vm_start,
			addr);

		up_write(&mm_cur->mmap_sem);
		mmput(mm_tgt);
		mmput(mm_cur);
		kfree(fpgd);
		return -ENOMEM;
	}

	/* log("flag 0x%08lx / prot 0x%08lx\n",
		vma->vm_flags, vma->vm_page_prot); */
	prot = vma->vm_page_prot;
	c_fpgd = addr;

	/* traverse the vaddr in a different way */
	for (
		vaddr = 0;
		vaddr < TASK_SIZE;
		vaddr += M_MEM_RANGE_PER_PTE, fpgd_idx++) {

		pgd_t *cpgd;
		pud_t *cpud;
		pmd_t *cpmd;

		if (vaddr == 0)
			vad = 0x1000;
		else
			vad = vaddr;

		cpgd = pgd_offset(mm_tgt, vad);
		log("[%08lx] *pgd=%08lx", vad, (unsigned long)pgd_val(*cpgd));

		if (pgd_none(*cpgd) || pgd_bad(*cpgd)) {
			log(", invalid pgd @ 0x%08lx\n", vad);
			*fpgd_idx = 0;
			continue;
		}

		/* pretend as if we have pud */
		cpud = pud_offset(cpgd, vad);
		if (PTRS_PER_PUD != 1)
			log(", *pud=%08lx", (unsigned long)pud_val(*cpud));

		if (pud_none(*cpud) || pud_bad(*cpud)) {
			log(", invalid pud @ 0x%08lx\n", vad);
			*fpgd_idx = 0;
			continue;
		}

		/* pretend as if we have pmd */
		cpmd = pmd_offset(cpud, vad);
		if (PTRS_PER_PMD != 1)
			log(", *pmd=%08lx", (long)pmd_val(*cpmd));

		if (pmd_none(*cpmd) || pmd_bad(*cpmd)) {
			log(", invalid pmd @ 0x%08lx\n", vad);
			*fpgd_idx = 0;
			continue;
		}

		/* get the real job done */
		log(", pte = 0x%08lx --> fpgd_idx = %p",
			(unsigned long)(*cpmd), fpgd_idx);
		*fpgd_idx = c_fpgd + ((*cpmd) - ((*cpmd) & 0xfffff000));

		/* do remapping */
		do_remap_single_page(
			vma,
			&c_fpgd,
			pmd_page(*cpmd),
			prot);
	}

	up_write(&mm_cur->mmap_sem);

/*__safe_exit:*/
	/* mm->mm_users was incremented in get_task_mm.
	 * Invoke mmput to decrement it back.
	 */
	mmput(mm_tgt);
	mmput(mm_cur);

	tmp = copy_to_user(
		(void *)fake_pgd,
		fpgd,
		M_ENTRIES_PGD * sizeof(unsigned long));

	if (tmp)
		retval = -ENOMEM;

	kfree(fpgd);
	return retval;
}
