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
#define ONLY_NONAME 1

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
	#ifndef TMEM
		#define TMEM
	#endif
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

static void print_elf_phdr_members(const char* indent, const ElfW(Phdr)* elf_phdr);

#ifdef TFILE
static void print_shdrs(const ElfW(Shdr)* shdr, const ElfW(Half) shnum, const unsigned char* filebin);
#endif

static void print_phdrs(const ElfW(Phdr)* phdrs, const int nphdrs, const unsigned char* baseadr);
static void print_dyns(const char* indent, const ElfW(Dyn)* dyns, const unsigned char* baseadr);
static void print_memory(const char* indent, const unsigned char* bytes, const int nbytes);

const ElfW(Ehdr)* elf_ehdr = NULL;

int main(int argc, char** argv)
{
	printf("pid\t%d\n", getpid());

	extern const void* _start;
	printf("_start\t%p\n", _start);
	printf("main\t%p\n", main);

#ifdef TFILE
	puts("\n*** target is FILE ***\n");

	const int fd = open(argv[0], O_RDONLY);
	struct stat st;
	fstat(fd, &st);
	unsigned char* filebin = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);

#else
	puts("\n*** target is MEMORY ***\n");

	const u_long at_base = getauxval(AT_BASE);
	const u_long at_phdr = getauxval(AT_PHDR);
	const u_long at_entry = getauxval(AT_ENTRY);

	printf("AT_BASE\t%p\n", (void*)at_base);
	printf("AT_PHDR\t%p\n", (void*)at_phdr);
	printf("AT_ENTRY\t%p\n", (void*)at_entry);
	printf("AT_SYSINFO_EHDR\t%p\n", (void*)getauxval(AT_SYSINFO_EHDR));
#endif

#ifdef TFILE
	elf_ehdr = (ElfW(Ehdr)*)filebin;
	printf("Elf_Ehdr (0x0)\n");
#else
	elf_ehdr = (ElfW(Ehdr)*)at_base;
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

	const ElfW(Phdr)* elf_phdrs = (ElfW(Phdr)*)&filebin[elf_ehdr->e_phoff];
	printf("Elf_Phdr (%p)\n", (void*)elf_ehdr->e_phoff);

#if 0
	for (int i=0; i<elf_ehdr->e_phnum; i++)
	{
		printf("\tElf_Phdr[%d]\n", i);
		print_elf_phdr_members("\t\t", &elf_phdrs[i]);
	}
#else
	print_phdrs(elf_phdrs, elf_ehdr->e_phnum, filebin);
#endif

	//
	printf("Elf_Shdr (%p)\n", (void*)elf_ehdr->e_shoff);

	print_shdrs((ElfW(Shdr)*)&filebin[elf_ehdr->e_shoff], elf_ehdr->e_shnum, filebin);

#else
	puts("Elf_Phdr");
	dl_iterate_phdr(phdr_callback, NULL);

#endif


#ifdef TFILE
#else
	const void* v_entry = (void*)at_entry;
#endif


#ifdef TFILE
	munmap(filebin, st.st_size);
	close(fd);
#endif	

	return 0;
}

#ifdef TFILE
static void print_syms(const char* indent, const ElfW(Sym)* syms, const int nsyms, const char* strtab)
{
	for (int i=0; i<nsyms; i++)
	{
		const ElfW(Sym)* sym = &syms[i];

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

		printf("%s\tst_other\t%d\n", indent, ELF64_ST_VISIBILITY(sym->st_other));
		printf("%s\tst_shndx\t%u\n", indent, sym->st_shndx);
	}
}

static void print_shdrs(const ElfW(Shdr)* elf_shdrs, const ElfW(Half) shnum, const unsigned char* filebin)
{
	const char* shstrtab = (char*)&filebin[elf_shdrs[elf_ehdr->e_shstrndx].sh_offset];

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
		printf("\t\tsh_addr\t%lu (%p)\n", elf_shdr->sh_addr, (void*)elf_shdr->sh_addr);
		printf("\t\tsh_offset\t%lu (%p)\n", elf_shdr->sh_offset, (void*)elf_shdr->sh_offset);
		printf("\t\tsh_size\t%lu (0x%lx)\n", elf_shdr->sh_size, elf_shdr->sh_size);
		printf("\t\tsh_link\t%u\n", elf_shdr->sh_link);
		printf("\t\tsh_info\t%u\n", elf_shdr->sh_info);
		printf("\t\tsh_addralign\t%lu\n", elf_shdr->sh_addralign);
		printf("\t\tsh_entsize\t%lu\n", elf_shdr->sh_entsize);

		const void* filepos = &filebin[elf_shdr->sh_offset];

		switch (elf_shdr->sh_type)
		{
			case SHT_DYNAMIC:
			{
				printf("\t\t* sh_type\tSHT_DYNAMIC\n");
				print_dyns("\t\t\t", (ElfW(Dyn)*)filepos, filebin);
				break;
			}

			case SHT_SYMTAB:
			case SHT_DYNSYM:
			{
				const ElfW(Sym)* syms = (ElfW(Sym)*)filepos;
				const int nsyms = elf_shdr->sh_size / elf_shdr->sh_entsize;
				const char* strtab = (char*)&filebin[elf_shdrs[elf_shdr->sh_link].sh_offset];

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

				const ElfW(Rela)* relas = (ElfW(Rela)*)filepos;
				const int nrelas = elf_shdr->sh_size / elf_shdr->sh_entsize;

				for (int i=0; i<nrelas; i++)
				{
					const ElfW(Rela)* rela = (ElfW(Rela)*)&relas[i];

					const int r_info_sym = ELF64_R_SYM(rela->r_info);

					printf("\t\t\tr_offset\t%p\n", (void*)rela->r_offset);
					printf("\t\t\tr_info(sym)\t%d\n", r_info_sym);

					if (dynsym && dynstrtab)
					{
						printf("\t\t\t\t'%s'\n", &dynstrtab[dynsym[r_info_sym].st_name]);
					}

					printf("\t\t\tr_info(type)\t%lu\n", ELF64_R_TYPE(rela->r_info));
					printf("\t\t\tr_addend\t%ld\n", rela->r_addend);
				}

				break;
			}

			case SHT_INIT_ARRAY:
			case SHT_FINI_ARRAY:
			{
				printf("\t\t* sh_type\t%s\n",
					elf_shdr->sh_type == SHT_INIT_ARRAY ? "SHT_INIT_ARRAY" : "SHT_FINI_ARRAY");

				for (int i=0; i<(elf_shdr->sh_size/elf_shdr->sh_entsize); i++)
				{
					const unsigned long offset = *((unsigned long*)(filepos + elf_shdr->sh_entsize * i));

					printf("\t\t\t[%d]=%p\n", i, (void*)offset);
					print_memory("\t\t\t", (unsigned char*)(filebin + offset), 16);
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

static void print_strtab(const char* indent, const char* pos)
{
	const char* start = pos;

	pos++;

	for (int i=0; *pos; i++)
	{
		printf("%s\t%d: (%ld) '%s'\n", indent, i, pos - start, pos);
		pos = pos + strlen(pos) + 1;

		if (i>20) {
			printf("%s\t...\n", indent);
			break;
		}
	}
}

static void print_memory(const char* indent, const unsigned char* bytes, const int nbytes)
{
	printf("%s\tmemory: ", indent);

	for (int i=0; i<nbytes; i++)
	{
		printf("%02x ", bytes[i]);
	}

	printf("...\n");
}

#ifdef TFILE
	#define D_UN_VAL(ba, v) (v.d_val)
#else
	#define D_UN_VAL(ba, v) ((ba) + (v.d_val))
#endif

static void print_dyns(const char* indent, const ElfW(Dyn)* dyns, const unsigned char* baseadr)
{
	const char* strtab = NULL;

	for (int i=0; dyns[i].d_un.d_val != DT_NULL; i++)
	{
		const ElfW(Dyn)* dyn = &dyns[i];

		if (dyn->d_tag == DT_STRTAB)
		{
#ifdef TFILE
			strtab = (char*)(baseadr + dyn->d_un.d_val);
#else
			strtab = (char*)dyn->d_un.d_ptr;
#endif

			break;
		}
	}

	//assert(strtab);

	ElfW(Addr) init_array = 0;
	ElfW(Addr) fini_array = 0;
	const ElfW(Sym)* symtabs = NULL;

	for (int idx=0; dyns[idx].d_un.d_val != DT_NULL; idx++)
	{
		const ElfW(Dyn)* dyn = &dyns[idx];

		switch (dyn->d_tag)
		{
			case DT_NEEDED:
			{
				printf("%sd_tag=DT_NEEDED\n", indent);
				printf("%s\t%lu", indent, dyn->d_un.d_val);
				if (strtab)
				{
					printf(" '%s'", &strtab[dyn->d_un.d_val]);
				}
				printf("\n");

				break;
			}

			case DT_STRTAB:
			{
				printf("%sd_tag=DT_STRTAB\n", indent);
				printf("%s\t%p\n", indent, (void*)dyn->d_un.d_ptr);

				print_strtab(indent, (char*)strtab);

				break;
			}

			case DT_STRSZ:
			{
				printf("%sd_tag=DT_STRSZ\n", indent);
				printf("%s\t%lu\n", indent, dyn->d_un.d_val);

				break;
			}

			case DT_INIT:
			{
				printf("%sd_tag=DT_INIT\n", indent);
				printf("%s\t%p (%p)\n",
					indent, (void*)dyn->d_un.d_ptr, (void*)D_UN_VAL(baseadr, dyn->d_un));

				print_memory(indent, (unsigned char*)(baseadr + dyn->d_un.d_val), 16);

				break;
			}

			case DT_FINI:
			{
				printf("%sd_tag=DT_FINI\n", indent);
				printf("%s\t%p (%p)\n",
					indent, (void*)dyn->d_un.d_ptr, (void*)D_UN_VAL(baseadr, dyn->d_un));

				print_memory(indent, baseadr + dyn->d_un.d_val, 16);

				break;
			}

			case DT_INIT_ARRAY:
			{
#ifdef TMEM
				init_array = dyn->d_un.d_ptr;
#endif

				printf("%sd_tag=DT_INIT_ARRAY\n", indent);
				printf("%s\t%p (%p)\n",
					indent, (void*)dyn->d_un.d_ptr, (void*)D_UN_VAL(baseadr, dyn->d_un));

				break;
			}

			case DT_FINI_ARRAY:
			{
#ifdef TMEM
				fini_array = dyn->d_un.d_ptr;
#endif

				printf("%sd_tag=DT_FINI_ARRAY\n", indent);
				printf("%s\t%p(%p)\n",
					indent, (void*)dyn->d_un.d_ptr, (void*)(baseadr + dyn->d_un.d_ptr));

				break;
			}

			case DT_INIT_ARRAYSZ:
			{
				printf("%sd_tag=DT_INIT_ARRAYSZ\n", indent);
				printf("%s\t%lu\n", indent, dyn->d_un.d_val);

				if (init_array)
				{
					const ElfW(Addr)* arr = (ElfW(Addr)*)(baseadr + init_array);

					for (int i=0; i<(dyn->d_un.d_val/sizeof(ElfW(Addr))); i++)
					{
						printf("%s\t[%d]=%p\n", indent, i, (void*)arr[i]);
						print_memory(indent, (unsigned char*)arr[i], 8);
					}
				}

				break;
			}

			case DT_FINI_ARRAYSZ:
			{
				printf("%sd_tag=DT_FINI_ARRAYSZ\n", indent);
				printf("%s\t%lu\n", indent, dyn->d_un.d_val);

				if (fini_array)
				{
					const ElfW(Addr)* arr = (ElfW(Addr)*)(baseadr + fini_array);

					for (int i=0; i<(dyn->d_un.d_val/sizeof(ElfW(Addr))); i++)
					{
						printf("%s\t[%d]=%p\n", indent, i, (void*)arr[i]);
						print_memory(indent, (unsigned char*)arr[i], 8);
					}
				}

				break;
			}

			case DT_SYMTAB:
			{
				symtabs = (const ElfW(Sym)*)dyn->d_un.d_ptr;

				printf("%sd_tag=DT_SYMTAB\n", indent);
				printf("%s\t%p\n", indent, (void*)dyn->d_un.d_ptr);

				break;
			}

			case DT_SYMENT:
			{
				printf("%sd_tag=DT_SYMENT\n", indent);
				printf("%s\t%lu:%lu\n", indent, dyn->d_un.d_val, sizeof(Elf64_Sym));

				break;
			}

			case DT_GNU_HASH:
			{
				// https://github.com/robgjansen/elf-loader/blob/master/vdl-lookup.c#L83
				// https://blogs.oracle.com/solaris/post/gnu-hash-elf-sections
				// https://flapenguin.me/elf-dt-gnu-hash
				// https://git.yoctoproject.org/prelink-cross/plain/trunk/src/ld-lookup.c?h=cross_prelink_r174

				printf("%sd_tag=DT_GNU_HASH\n", indent);
				printf("%s\t%p\n", indent, (void*)dyn->d_un.d_ptr);

				break;
			}

			case DT_HASH:
			{
				// https://github.com/robgjansen/elf-loader/blob/master/vdl-lookup.c#L118

				printf("%sd_tag=DT_HASH\n", indent);
				printf("%s\t%p\n", indent, (void*)dyn->d_un.d_ptr);

				break;
			}

			default:
			{
				printf("%sd_tag=%ld (%p)\n", indent, dyn->d_tag, (void*)dyn->d_tag);
				break;
			}
		}
	}
}

static void print_phdrs(const ElfW(Phdr)* phdrs, const int nphdrs, const unsigned char* baseadr)
{
	for (int j = 0; j < nphdrs; j++)
	{
		const ElfW(Phdr)* phdr = &phdrs[j];
		printf("\tElf_Phdr[%d] (%p)\n", j, phdr);

		print_elf_phdr_members("\t\t", phdr);

		void* p_vaddr = (void*)(baseadr + phdr->p_vaddr);

		printf("\t\t* p_vaddr=%p\n", p_vaddr);

		switch (phdr->p_type)
		{
			case PT_DYNAMIC:
			{
				puts("\t\t* p_type=PT_DYNAMIC");
#ifdef TFILE
				print_dyns("\t\t\t", (ElfW(Dyn)*)(baseadr + phdr->p_offset), baseadr);
#else
				print_dyns("\t\t\t", (ElfW(Dyn)*)p_vaddr, baseadr);
#endif
				break;
			}

			case PT_INTERP:
			{
				puts("\t\t* p_type=PT_INTERP");
				printf("\t\t\t%s\n", (char*)p_vaddr);
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
}

#ifdef TMEM
static int phdr_callback(struct dl_phdr_info *info, size_t size, void *data)
{
	if (info->dlpi_name[0] != '\0')
	{
#ifdef ONLY_NONAME
		return 0;
#endif
	}

	printf("name='%s' (%d segments) base=%p\n",
		info->dlpi_name, info->dlpi_phnum, (void*)info->dlpi_addr);

	print_phdrs(info->dlpi_phdr, info->dlpi_phnum, (unsigned char*)info->dlpi_addr);


	return 0;
}
#endif

static void print_elf_phdr_members(const char* indent, const ElfW(Phdr)* elf_phdr)
{
	printf("%sp_type\t0x%x\n", indent, elf_phdr->p_type);
	printf("%sp_offset\t%lu (0x%lx)\n", indent, elf_phdr->p_offset, elf_phdr->p_offset);
	printf("%sp_vaddr\t%lu (%p)\n", indent, elf_phdr->p_vaddr, (void*)elf_phdr->p_vaddr);
	printf("%sp_paddr\t%lu (%p)\n", indent, elf_phdr->p_paddr, (void*)elf_phdr->p_paddr);
	printf("%sp_filesz\t%lu\n", indent, elf_phdr->p_filesz);
	printf("%sp_memsz\t%lu\n", indent, elf_phdr->p_memsz);
	printf("%sp_flags\t0x%x\n", indent, elf_phdr->p_flags);
	printf("%sp_align\t%lu\n", indent, elf_phdr->p_align);
}

