#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>

#if 0
#define dbg	printf
#else
#define dbg(...)
#endif

#define PAGE_SIZE	(1 << 12)
#define PGD_ENTRY_NUM	(1 << 11)
#define PTE_ENTRY_NUM	(1 << 9)
#define PGD_USER_ENTRY_NUM	(PGD_ENTRY_NUM - (1 << 9))
#define PTE_LENGTH		(PAGE_SIZE * PGD_USER_ENTRY_NUM)

static inline void print_error(void)
{
	printf("error: %s\n", strerror(errno));
}

static void print_table_fields(void)
{
	printf("[index]");
	printf("     [virt]");
	printf("     [phys]");
	printf(" [young bit]");
	printf(" [file bit]");
	printf(" [dirty bit]");
	printf(" [r-o bit]");
	printf(" [xn bit]");
	printf("\n");
}

/* Temporary shift. Correct later */
#define PGD_INDEX(va)	((va) >> 21)
#define PTE_INDEX(va)	(((va) >> 12) & ((1 << 9) - 1))
#define ADDR_OFFSET(va)	((va) & (PAGE_SIZE - 1))
#define PTE_LX_BASE(pgd)	((pgd) & 0xfffff400)
#define PTE_HW_BASE(pgd)	((pgd) & 0xfffffc00)

#define PTE_PFN(pte)	(((pte) >> 12) & ((1 << 20) - 1))
#define PHY_ADDR(pte, va)	((PTE_PFN(pte) << 12) | ADDR_OFFSET(va))
#define PTE_YOUNG(pte)	(((pte) >> 1) & 1)
#define PTE_FILE(pte)	(((pte) >> 2) & 1)
#define PTE_DIRTY(pte)	(((pte) >> 6) & 1)
#define PTE_RO(pte)	(((pte) >> 7) & 1)
#define PTE_XN(pte)	(((pte) >> 9) & 1)

static unsigned long retrieve_pte(
		unsigned long pgd_base, unsigned long va, int hw)
{
	unsigned long pgd_idx = 0;
	unsigned long pte_idx = 0;
	unsigned long *p_pgd;
	unsigned long pte_base = 0;
	unsigned long *p_pte;
	unsigned long pte = 0;

	pgd_idx = PGD_INDEX(va);
	pte_idx = PTE_INDEX(va);
	dbg("page info - 0x%08x (0x%03x 0x%03x)\n",
			(unsigned int)va,
			(unsigned int)pgd_idx,
			(unsigned int)pte_idx);

	/* Retrieve PTE *//*
	Mark for moving p_pgd with 8 bytes
	p_pgd = (unsigned long *)(pgd_base + pgd_idx * sizeof(unsigned long));*/
	p_pgd = (unsigned long *)
		(pgd_base + pgd_idx * sizeof(unsigned long));
	dbg("0x%08x", (unsigned int)p_pgd);
	if (hw)
		pte_base = PTE_HW_BASE(*p_pgd);
	else
		pte_base = PTE_LX_BASE(*p_pgd);
	dbg("\t0x%08x(0x%08x)", (unsigned int)pte_base, (unsigned int)(*p_pgd));

	if (pte_base) {
		p_pte = (unsigned long *)
			(pte_base + pte_idx * sizeof(unsigned long));
		dbg("\t0x%08x", (unsigned int)p_pte);
		pte = *p_pte;
		dbg("\t0x%08x", (unsigned int)pte);
	}

	dbg("\n");

	return pte;
}

static void print_table_entry(unsigned long va, unsigned long pte, int hw)
{
	if (hw)
		printf("H 0x%03x", (unsigned int)PGD_INDEX(va));
	else
		printf("  0x%03x", (unsigned int)PGD_INDEX(va));
	printf(" 0x%08x", (unsigned int)va);
	printf(" 0x%08x", (unsigned int)PHY_ADDR(pte, va));
	printf("           %d", (int)PTE_YOUNG(pte));
	printf("          %d", (int)PTE_FILE(pte));
	printf("           %d", (int)PTE_DIRTY(pte));
	printf("         %d", (int)PTE_RO(pte));
	printf("        %d", (int)PTE_XN(pte));
	printf("\n");
}

static int dump_page_table(unsigned long pgd_base, int verbose)
{
	int retval = 0;
	unsigned long i = 0;
	unsigned long va = 0;
	unsigned long pte;

	if (!pgd_base)
		return -1;

	print_table_fields();

	for (i = 0; i < ((PGD_USER_ENTRY_NUM - 8) * PTE_ENTRY_NUM); i++) {
		va = i << 12;
		pte = retrieve_pte(pgd_base, va, 0);

		/* Format output */
		if (pte || verbose)
			print_table_entry(va, pte, 0);
#if 0	/* Check with HW part */
		pte = retrieve_pte(pgd_base, va, 1);

		/* Format output */
		if (pte || verbose)
			print_table_entry(va, pte, 1);
#endif
	}

	return retval;
}

static int interact_page_table(unsigned long pgd_base)
{
	int retval = 0;
	unsigned long pgd_idx = 0;
	unsigned long pte_idx = 0;
	unsigned long pte;
	char input[64];
	char *exit;

	while (1) {
		printf("pgd index: ");
		scanf("%s", input);
		if (!strcmp(input, "q"))
			break;
		pgd_idx = strtol(input, &exit, 0) & (PGD_ENTRY_NUM - 1);
		printf("pte index: ");
		scanf("%s", input);
		if (!strcmp(input, "q"))
			break;
		pte_idx = strtol(input, &exit, 0) & (PTE_ENTRY_NUM - 1);
		dbg("pgd 0x%03x pte 0x%03x\n",
				(unsigned int)pgd_idx,
				(unsigned int)pte_idx);

		pte = retrieve_pte(
				pgd_base, (pgd_idx << 21) + (pte_idx << 12), 0);

		print_table_fields();
		print_table_entry((pgd_idx << 21) + (pte_idx << 12), pte, 0);
	}

	return retval;
}

int main(int argc, char **argv)
{
	int retval = 0;
	int interact = 0;
	int verbose = 0;
	int pid = 0;
	unsigned long pgd = 0;
	void *addr = NULL;

	if (argc > 1 && strcmp(argv[1], "-v") == 0)
		verbose = 1;
	else if (argc > 1 && strcmp(argv[1], "-i") == 0)
		interact = 1;

	pid = (argc > (interact + verbose + 1)) ?
		abs(atoi(argv[interact + verbose + 1])) : -1;

	dbg("interact = %d / verbose = %d pid = %d\n", interact, verbose, pid);

	/* Get aligned buffer for fake PGD */
	retval = posix_memalign((void **)&pgd, PGD_ENTRY_NUM,
			PGD_ENTRY_NUM * sizeof(unsigned long));
	dbg("pgd 0x%08x: %d (%d)\n", (unsigned int)pgd,
			PGD_ENTRY_NUM * sizeof(unsigned long), PGD_ENTRY_NUM);
	if (retval < 0) {
		print_error();
		goto __exit;
	}

	/********** WARNING **********/
	/* very buggy --> we should not allocate and the size is not correct as well
	 * Get aligned buffer for remap PTE
	 *
	 * void *mmap (void *__addr, size_t __len, int __prot,
	 * int __flags, int __fd, __off_t __offset)
	 */
	addr = mmap(NULL, PTE_LENGTH , PROT_READ,
			MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	dbg("addr 0x%08x: %d\n", (unsigned int)addr, PTE_LENGTH);
	if (addr == MAP_FAILED) {
		print_error();
		goto __exit;
	}

	dbg("Calling syscall\n");

	/* Request page table */
	retval = syscall(__NR_expose_page_table, pid, pgd, addr);
	if (retval < 0) {
		print_error();
		goto __exit;
	}

	/* Translate and dump the page table */
	if (interact)
		retval = interact_page_table(pgd);
	else
		retval = dump_page_table(pgd, verbose);

__exit:
	if (addr) {
		retval = munmap((void *)addr, PTE_LENGTH);
		if (retval < 0)
			print_error();
	}
	if (pgd)
		free((void *)pgd);

	return retval;
}
