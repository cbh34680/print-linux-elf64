/*
 * user@asm:~/print-linux-elf64(1:477)$ uname -a
 * Linux asm 5.10.0-13-amd64 #1 SMP Debian 5.10.106-1 (2022-03-17) x86_64 GNU/Linux
 *

gcc -ggdb -O0 -o exe src.c && ./exe
clear; gcc -E src.c > src.pc; gcc -ggdb -O0 -c src.c && gcc -o exe src.o && ./exe
clear; gcc -E src.c > src.pc; gcc -Wformat -Wformat-signedness -ggdb -O0 -c src.c && gcc -o exe src.o && ./exe

 */
#define _GNU_SOURCE

//#define TFILE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>
#include <alloca.h>
#include <sys/types.h>
#include <sys/stat.h>

#ifdef TFILE
	#include <sys/mman.h>
#else
	#define TMEM
#endif

#include <link.h>
#include <elf.h>
#include <sys/auxv.h>

#ifdef TMEM
static int phdr_callback(struct dl_phdr_info *info, size_t size, void *data);
#endif

__attribute__ ((constructor)) static void construct1()
{
	puts("construct1");
}

__attribute__ ((constructor)) static void construct2()
{
	puts("construct2");
}

__attribute__ ((destructor)) static void destruct1()
{
	puts("destruct1");
}

__attribute__ ((destructor)) static void destruct2()
{
	puts("destruct2");
}

static void print_elf_phdr_members(const char const* indent, const ElfW(Phdr)* elf_phdr);
static void print_elf_shdrs(const ElfW(Shdr)* shdr, const ElfW(Half) shnum, const char const* filebin);

#ifdef TFILE
static void print_dyns_sht(const char const* indent, const ElfW(Dyn) const* dyns, const char const* base_addr);
#else
static void print_dyns_pt(const char const* indent, const ElfW(Dyn) const* dyns, const char const* base_addr);
#endif

const ElfW(Ehdr)* elf_ehdr = NULL;

int main(int argc, char** argv)
{
	printf("pid\t%d\n", getpid());

	extern const void* _start;
	printf("_start\t%p\n", _start);
	printf("main\t%p\n", main);

#ifdef TFILE
	puts("\n*** target is FILE\n");

	const int fd = open(argv[0], O_RDONLY);
	struct stat st;
	fstat(fd, &st);
	char* filebin = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);

#else
	puts("\n*** target is MEMORY\n");

	const u_long at_base = getauxval(AT_BASE);
	const u_long at_phdr = getauxval(AT_PHDR);
	const u_long at_entry = getauxval(AT_ENTRY);

	printf("AT_BASE\t%p\n", at_base);
	printf("AT_PHDR\t%p\n", at_phdr);
	printf("AT_ENTRY\t%p\n", at_entry);
	printf("AT_SYSINFO_EHDR\t%p\n", getauxval(AT_SYSINFO_EHDR));
#endif

#ifdef TFILE
	//elf_ehdr = (const Elf64_Ehdr*)filebin;
	elf_ehdr = (const ElfW(Ehdr)*)filebin;
	printf("Elf_Ehdr (0x0)\n");
#else
	//elf_ehdr = (const Elf64_Ehdr*)at_base;
	elf_ehdr = (const ElfW(Ehdr)*)at_base;
	printf("Elf_Ehdr (%p)\n", elf_ehdr);
#endif

	puts("\te_ident");
	assert(elf_ehdr->e_ident[EI_MAG0] == 0x7f);
	assert(elf_ehdr->e_ident[EI_MAG1] == 'E');
	assert(elf_ehdr->e_ident[EI_MAG2] == 'L');
	assert(elf_ehdr->e_ident[EI_MAG3] == 'F');
	assert(elf_ehdr->e_ident[EI_CLASS] == 2);
	assert(elf_ehdr->e_ident[EI_DATA] == ELFDATA2LSB);
	assert(elf_ehdr->e_ident[EI_VERSION] == EV_CURRENT);

	printf("\t\tEI_OSABI\t%d\n", elf_ehdr->e_ident[EI_OSABI]);
	printf("\t\tEI_ABIVERSION\t%d\n", elf_ehdr->e_ident[EI_ABIVERSION]);

	printf("\te_type\t%d\n", elf_ehdr->e_type);
	assert(elf_ehdr->e_machine == 62);
	assert(elf_ehdr->e_version == 1);
	printf("\te_entry\t%p\n", (void*)elf_ehdr->e_entry);
	printf("\te_phoff\t%lu\n", elf_ehdr->e_phoff);
	printf("\te_shoff\t%lu (%p)\n", elf_ehdr->e_shoff, (void*)elf_ehdr->e_shoff);
	assert(elf_ehdr->e_flags == 0);

	printf("\te_ehsize\t%u\n", elf_ehdr->e_ehsize);
	assert(elf_ehdr->e_ehsize == sizeof(ElfW(Ehdr)));
	printf("\te_phentsize\t%u\n", elf_ehdr->e_phentsize);
	assert(elf_ehdr->e_phentsize == sizeof(ElfW(Phdr)));
	printf("\te_phnum\t%u\n", elf_ehdr->e_phnum);
	printf("\te_shentsize\t%u\n", elf_ehdr->e_shentsize);
	assert(elf_ehdr->e_shentsize == sizeof(ElfW(Shdr)));
	printf("\te_shnum\t%u\n", elf_ehdr->e_shnum);
	printf("\te_shstrndx\t%u\n", elf_ehdr->e_shstrndx);

#ifdef TFILE

	//const Elf64_Phdr* elf_phdrs = (const Elf64_Phdr*)&filebin[elf_ehdr->e_phoff];
	const ElfW(Phdr)* elf_phdrs = (const ElfW(Phdr)*)&filebin[elf_ehdr->e_phoff];
	printf("Elf_Phdr (%p)\n", (void*)elf_ehdr->e_phoff);

	void* p_vaddr = filebin;

	for (int i=0; i<elf_ehdr->e_phnum; i++)
	{
		const ElfW(Phdr)* elf_phdr = &elf_phdrs[i];

		printf("\tElf_Phdr[%d]\n", i);

		print_elf_phdr_members("\t\t", &elf_phdrs[i]);
	}

	printf("Elf_Shdr (%p)\n", (void*)elf_ehdr->e_shoff);

	print_elf_shdrs((const ElfW(Shdr)*)&filebin[elf_ehdr->e_shoff], elf_ehdr->e_shnum, filebin);

#else
	puts("Elf_Phdr");
	dl_iterate_phdr(phdr_callback, NULL);
#endif


#ifdef TFILE
#else
	const void* v_entry = (const void*)at_entry;
#endif


#ifdef TFILE
	munmap(filebin, st.st_size);
	close(fd);
#endif	

	return 0;
}

#ifdef TFILE
static void print_syms(const char const* indent, const ElfW(Sym) const* syms, const int nsyms, const char const* strtab)
{
	for (int i=0; i<nsyms; i++)
	{
		const ElfW(Sym) const* sym = &syms[i];

		printf("%sElf_Sym[%d]\n", indent, i);
		printf("%s\tst_name\t%u '%s'\n", indent, sym->st_name, &strtab[sym->st_name]);
		printf("%s\tst_value\t%p\n", indent, (void*)sym->st_value);
		printf("%s\tst_size\t%lu\n", indent, sym->st_size);

		const unsigned char st_info_bind = ELF64_ST_BIND(sym->st_info);
		switch (st_info_bind)
		{
			case STB_LOCAL:
				printf("%s\tst_info(bind)\tSTB_LOCAL\n", indent);
				break;
			case STB_GLOBAL:
				printf("%s\tst_info(bind)\tSTB_GLOBAL\n", indent);
				break;
			case STB_WEAK:
				printf("%s\tst_info(bind)\tSTB_WEAK\n", indent);
				break;
			default:
				printf("%s\tst_info(bind)\t%u\n", indent, st_info_bind);
				break;
		}
		const unsigned char st_info_type = ELF64_ST_TYPE(sym->st_info);
		switch (st_info_type)
		{
			case STT_NOTYPE:
				printf("%s\tst_info(type)\tSTT_NOTYPE\n", indent);
				break;
			case STT_OBJECT:
				printf("%s\tst_info(type)\tSTT_OBJECT\n", indent);
				break;
			case STT_FUNC:
				printf("%s\tst_info(type)\tSTT_FUNC\n", indent);
				break;
			case STT_SECTION:
				printf("%s\tst_info(type)\tSTT_SECTION\n", indent);
				break;
			case STT_FILE:
				printf("%s\tst_info(type)\tSTT_FILE\n", indent);
				break;
			default:
				printf("%s\tst_info(type)\t%u\n", indent, st_info_type);
				break;
		}

		printf("%s\tst_other\t%lu\n", indent, ELF64_ST_VISIBILITY(sym->st_other));
		printf("%s\tst_shndx\t%u\n", indent, sym->st_shndx);
	}
}

static void print_elf_shdrs(const ElfW(Shdr)* elf_shdrs, const ElfW(Half) shnum, const char const* filebin)
{
	const char const* shstrtab = &filebin[elf_shdrs[elf_ehdr->e_shstrndx].sh_offset];

	const ElfW(Sym)* dynsym = NULL;
	const char* dynstrtab = NULL;

	for (int i=0; i<shnum; i++)
	{
		const ElfW(Shdr)* elf_shdr = &elf_shdrs[i];

		printf("\tElf_Shdr[%d]\n", i);

		printf("\t\tsh_name\t%u", elf_shdr->sh_name);
		if (shstrtab)
		{
			printf(" '%s'", &shstrtab[elf_shdr->sh_name]);
		}
		puts("");

		printf("\t\tsh_type\t%u (0x%x)\n", elf_shdr->sh_type, elf_shdr->sh_type);
		printf("\t\tsh_flags\t0x%lx\n", elf_shdr->sh_flags);
		if (elf_shdr->sh_flags & SHF_INFO_LINK)
		{
			puts("\t\t\tSHF_INFO_LINK");
		}
		printf("\t\tsh_addr\t%p\n", (void*)elf_shdr->sh_addr);
		printf("\t\tsh_offset\t%d (%p)\n", elf_shdr->sh_offset, (void*)elf_shdr->sh_offset);
		printf("\t\tsh_size\t%lu (0x%lx)\n", elf_shdr->sh_size, elf_shdr->sh_size);
		printf("\t\tsh_link\t%u\n", elf_shdr->sh_link);
		printf("\t\tsh_info\t%u\n", elf_shdr->sh_info);
		printf("\t\tsh_addralign\t%lu\n", elf_shdr->sh_addralign);
		printf("\t\tsh_entsize\t%lu\n", elf_shdr->sh_entsize);

		const void const* filepos = &filebin[elf_shdr->sh_offset];

		switch (elf_shdr->sh_type)
		{
			case SHT_DYNAMIC:
			{
				printf("\t\t* sh_type\tSHT_DYNAMIC\n");
				print_dyns_sht("\t\t\t", (ElfW(Dyn)*)filepos, filebin);
				break;
			}

			case SHT_SYMTAB:
			case SHT_DYNSYM:
			{
				const ElfW(Sym) const* syms = (ElfW(Sym)*)filepos;
				const int nsyms = elf_shdr->sh_size / elf_shdr->sh_entsize;
				const char const* strtab = &filebin[elf_shdrs[elf_shdr->sh_link].sh_offset];

				if (elf_shdr->sh_type == SHT_DYNSYM)
				{
					dynsym = syms;
					dynstrtab = strtab;

					puts("\t\t* sh_type\tSHT_DYNSYM");
				}
				else
				{
					puts("\t\t* sh_type\tSHT_SYMTAB");
				}

				print_syms("\t\t\t", syms, nsyms, strtab);
				break;
			}

			case SHT_RELA:
			{
				printf("\t\t* sh_type\tSHT_RELA\n");

				const ElfW(Rela) const* relas = (ElfW(Rela)*)filepos;
				const int nrelas = elf_shdr->sh_size / elf_shdr->sh_entsize;

				for (int i=0; i<nrelas; i++)
				{
					const ElfW(Rela) const* rela = (ElfW(Rela)*)&relas[i];

					const int r_info_sym = ELF64_R_SYM(rela->r_info);

					printf("\t\t\tr_offset\t%p\n", rela->r_offset);
					printf("\t\t\tr_info(sym)\t%d\n", r_info_sym);

					if (dynsym && dynstrtab)
					{
						printf("\t\t\t\t'%s'\n", &dynstrtab[dynsym[r_info_sym].st_name]);
					}

					printf("\t\t\tr_info(type)\t%llu\n", ELF64_R_TYPE(rela->r_info));
					printf("\t\t\tr_addend\t%lld\n", rela->r_addend);
				}

				break;
			}

			default:
			{
				break;
			}
		}
	}
}

#endif

static void print_strtab(const char const* indent, const char* pos)
{
	const char const* start = pos;

	pos++;

	for (int i=0; *pos; i++)
	{
		printf("%s\t%d: (%lu) '%s'\n", indent, i, pos - start, pos);
		pos = pos + strlen(pos) + 1;

		if (i>20) {
			printf("%s\t...\n", indent);
			break;
		}
	}
}

#ifdef TFILE
static void print_dyns_sht(const char const* indent, const ElfW(Dyn) const* dyns, const char const* base_addr)
{
	const char* strtab = NULL;

	for (int i=0; dyns[i].d_un.d_val != DT_NULL; i++)
	{
		const ElfW(Dyn) const* dyn = &dyns[i];

		if (dyn->d_tag == DT_STRTAB)
		{
			strtab = (char*)base_addr + dyn->d_un.d_val;
			break;
		}
	}

	assert(strtab);

	const ElfW(Sym)* symtabs = NULL;

	for (int i=0; dyns[i].d_un.d_val != DT_NULL; i++)
	{
		const ElfW(Dyn) const* dyn = &dyns[i];

		switch (dyn->d_tag)
		{
			case DT_NEEDED:
			{
				printf("%sd_tag=DT_NEEDED\n", indent);

				break;
			}

			case DT_STRTAB:
			{
				printf("%sd_tag=DT_STRTAB\n", indent);
				printf("%s\t%d\n", indent, dyn->d_un.d_val);

				print_strtab(indent, base_addr + dyn->d_un.d_val);

				break;
			}

			case DT_STRSZ:
			{
				printf("%sd_tag=DT_STRSZ\n", indent);
				printf("%s\t%d\n", indent, dyn->d_un.d_val);

				break;
			}

			case DT_INIT:
			{
				printf("%sd_tag=DT_INIT\n", indent);

				break;
			}

			case DT_FINI:
			{
				printf("%sd_tag=DT_FINI\n", indent);

				break;
			}

			case DT_INIT_ARRAY:
			{
				printf("%sd_tag=DT_INIT_ARRAY\n", indent);

				break;
			}

			case DT_FINI_ARRAY:
			{
				printf("%sd_tag=DT_FINI_ARRAY\n", indent);

				break;
			}

			case DT_INIT_ARRAYSZ:
			{
				printf("%sd_tag=DT_INIT_ARRAYSZ\n", indent);

				break;
			}

			case DT_FINI_ARRAYSZ:
			{
				printf("%sd_tag=DT_FINI_ARRAYSZ\n", indent);

				break;
			}

			case DT_SYMTAB:
			{
				printf("%sd_tag=DT_SYMTAB\n", indent);

				break;
			}

			case DT_SYMENT:
			{
				printf("%sd_tag=DT_SYMENT\n", indent);

				break;
			}

			case DT_GNU_HASH:
			{
				// https://github.com/robgjansen/elf-loader/blob/master/vdl-lookup.c#L83
				// https://blogs.oracle.com/solaris/post/gnu-hash-elf-sections
				// https://flapenguin.me/elf-dt-gnu-hash
				// https://git.yoctoproject.org/prelink-cross/plain/trunk/src/ld-lookup.c?h=cross_prelink_r174

				printf("%sd_tag=DT_GNU_HASH\n", indent);

				break;
			}

			case DT_HASH:
			{
				// https://github.com/robgjansen/elf-loader/blob/master/vdl-lookup.c#L118

				printf("%sd_tag=DT_HASH\n", indent);

				break;
			}

			default:
			{
				printf("%sd_tag=%d (0x%x)\n", indent, dyn->d_tag, dyn->d_tag);
				break;
			}
		}
	}
}

#else
static void print_dyns_pt(const char const* indent, const ElfW(Dyn) const* dyns, const char const* base_addr)
{
	const char* strtab = NULL;

	for (int i=0; dyns[i].d_un.d_val != DT_NULL; i++)
	{
		const ElfW(Dyn) const* dyn = &dyns[i];

		if (dyn->d_tag == DT_STRTAB)
		{
			strtab = (char*)dyn->d_un.d_ptr;
			break;
		}
	}

	assert(strtab);

	ElfW(Addr) init_array = 0;
	ElfW(Addr) fini_array = 0;
	const ElfW(Sym)* symtabs = NULL;

	for (int idx=0; dyns[idx].d_un.d_val != DT_NULL; idx++)
	{
		const ElfW(Dyn) const* dyn = &dyns[idx];

		switch (dyn->d_tag)
		{
			case DT_NEEDED:
			{
				printf("%sd_tag=DT_NEEDED\n", indent);
				printf("%s\t%lu '%s'\n", indent, dyn->d_un.d_val, &strtab[dyn->d_un.d_val]);

				break;
			}

			case DT_STRTAB:
			{
				printf("%sd_tag=DT_STRTAB\n", indent);
				printf("%s\t%p\n", indent, dyn->d_un.d_ptr);

				strtab = (char*)dyn->d_un.d_ptr;

				print_strtab(indent, (char*)strtab);

				break;
			}

			case DT_STRSZ:
			{
				printf("%sd_tag=DT_STRSZ\n", indent);
				printf("%s\t%d\n", indent, dyn->d_un.d_val);

				break;
			}

			case DT_INIT:
			{
				printf("%sd_tag=DT_INIT\n", indent);
				printf("%s\t%p(%p)\n", indent, (void*)dyn->d_un.d_ptr, (void*)(base_addr + dyn->d_un.d_ptr));

				break;
			}

			case DT_FINI:
			{
				printf("%sd_tag=DT_FINI\n", indent);
				printf("%s\t%p(%p)\n", indent, (void*)dyn->d_un.d_ptr, (void*)(base_addr + dyn->d_un.d_ptr));

				break;
			}

			case DT_INIT_ARRAY:
			{
				init_array = dyn->d_un.d_ptr;

				printf("%sd_tag=DT_INIT_ARRAY\n", indent);
				printf("%s\t%p(%p)\n", indent, (void*)dyn->d_un.d_ptr, (void*)(base_addr + dyn->d_un.d_ptr));

				break;
			}

			case DT_FINI_ARRAY:
			{
				fini_array = dyn->d_un.d_ptr;

				printf("%sd_tag=DT_FINI_ARRAY\n", indent);
				printf("%s\t%p(%p)\n", indent, dyn->d_un.d_ptr, (void*)(base_addr + dyn->d_un.d_ptr));

				break;
			}

			case DT_INIT_ARRAYSZ:
			{
				printf("%sd_tag=DT_INIT_ARRAYSZ\n", indent);
				printf("%s\t%d\n", indent, dyn->d_un.d_val);

				if (init_array)
				{
					const ElfW(Addr) const* arr = (ElfW(Addr)*)(base_addr + init_array);

					for (int i=0; i<(dyn->d_un.d_val/sizeof(ElfW(Addr))); i++)
					{
						printf("%s\t[%d]=%p\n", indent, i, arr[i]);
					}
				}

				break;
			}

			case DT_FINI_ARRAYSZ:
			{
				printf("%sd_tag=DT_FINI_ARRAYSZ\n", indent);
				printf("%s\t%d\n", indent, dyn->d_un.d_val);

				if (fini_array)
				{
					const ElfW(Addr) const* arr = (ElfW(Addr)*)(base_addr + fini_array);

					for (int i=0; i<(dyn->d_un.d_val/sizeof(ElfW(Addr))); i++)
					{
						printf("%s\t[%d]=%p\n", indent, i, arr[i]);
					}
				}

				break;
			}

			case DT_SYMTAB:
			{
				symtabs = (const ElfW(Sym)*)dyn->d_un.d_ptr;

				printf("%sd_tag=DT_SYMTAB\n", indent);
				printf("%s\t%p\n", indent, dyn->d_un.d_ptr);

				break;
			}

			case DT_SYMENT:
			{
				printf("%sd_tag=DT_SYMENT\n", indent);
				printf("%s\t%d:%d\n", indent, dyn->d_un.d_val, sizeof(Elf64_Sym));

				break;
			}

			case DT_GNU_HASH:
			{
				// https://github.com/robgjansen/elf-loader/blob/master/vdl-lookup.c#L83
				// https://blogs.oracle.com/solaris/post/gnu-hash-elf-sections
				// https://flapenguin.me/elf-dt-gnu-hash
				// https://git.yoctoproject.org/prelink-cross/plain/trunk/src/ld-lookup.c?h=cross_prelink_r174

				printf("%sd_tag=DT_GNU_HASH\n", indent);
				printf("%s\t%p\n", indent, dyn->d_un.d_ptr);

				break;
			}

			case DT_HASH:
			{
				// https://github.com/robgjansen/elf-loader/blob/master/vdl-lookup.c#L118

				printf("%sd_tag=DT_HASH\n", indent);
				printf("%s\t%p\n", indent, dyn->d_un.d_ptr);

				break;
			}

			default:
			{
				printf("%sd_tag=%d (0x%x)\n", indent, dyn->d_tag, dyn->d_tag);
				break;
			}
		}
	}
}
#endif

#ifdef TMEM
static int phdr_callback(struct dl_phdr_info *info, size_t size, void *data)
{
	if (info->dlpi_name[0] != '\0')
	{
		return 0;
	}

	printf("name='%s' (%d segments) base=%p\n", info->dlpi_name, info->dlpi_phnum, info->dlpi_addr);

	for (int j = 0; j < info->dlpi_phnum; j++)
	{
		//void* p_vaddr = (void*)(info->dlpi_addr + info->dlpi_phdr[j].p_vaddr);

		const ElfW(Phdr)* elf_phdr = &info->dlpi_phdr[j];
		printf("\tElf_Phdr[%d] (%p)\n", j, elf_phdr);

		print_elf_phdr_members("\t\t", elf_phdr);

		void* p_vaddr = (void*)(info->dlpi_addr + elf_phdr->p_vaddr);

		printf("\t\t* p_vaddr=%p\n", p_vaddr);

		switch (elf_phdr->p_type)
		{
			case PT_DYNAMIC:
			{
				puts("\t\t* p_type=PT_DYNAMIC");
				print_dyns_pt("\t\t\t", (ElfW(Dyn)*)p_vaddr, (char*)info->dlpi_addr);
				break;
			}

			case PT_INTERP:
			{
				puts("\t\t* p_type=PT_INTERP");
				printf("\t\t\t%s\n", p_vaddr);
				break;
			}

			case PT_PHDR:
			{
				puts("\t\t* p_type=PT_PHDR");
				print_elf_phdr_members("\t\t\t", p_vaddr);
				break;
			}
		}
	}

	return 0;
}
#endif

static void print_elf_phdr_members(const char const* indent, const ElfW(Phdr)* elf_phdr)
{
	printf("%sp_type\t0x%x\n", indent, elf_phdr->p_type);
	printf("%sp_offset\t%u (0x%x)\n", indent, elf_phdr->p_offset, elf_phdr->p_offset);
	printf("%sp_vaddr\t%u (%p)\n", indent, elf_phdr->p_vaddr, elf_phdr->p_vaddr);
	printf("%sp_paddr\t%u (%p)\n", indent, elf_phdr->p_paddr, elf_phdr->p_paddr);
	printf("%sp_filesz\t%u\n", indent, elf_phdr->p_filesz);
	printf("%sp_memsz\t%u\n", indent, elf_phdr->p_memsz);
	printf("%sp_flags\t0x%x\n", indent, elf_phdr->p_flags);
	printf("%sp_align\t%u\n", indent, elf_phdr->p_align);
}

