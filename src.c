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
//#define ONLY_NONAME

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

typedef unsigned char byte_t;

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

void export_func(void)
{
	puts("export");
}

int g_int = 123;

static void print_phdrs(const ElfW(Phdr)* phdrs, const int nphdrs, const byte_t* baseadr);
static void print_phdr_members(const char* indent, const ElfW(Phdr)* elf_phdr);
static void print_dyns(const char* indent, const ElfW(Dyn)* dyns, const byte_t* baseadr);
static void print_syms(const char* indent, const ElfW(Sym)* syms, const int start, const int nsyms, const char* strtab);
static void print_note(const char* indent, const void* datapos, const ElfW(Xword) p_filesz);

#ifdef TFILE
static void print_shdrs(const ElfW(Ehdr)* ehdr, const ElfW(Shdr)* shdr, const ElfW(Half) shnum, const byte_t* filebin);
static const char* shdr_type2str(const ElfW(Word) type);
#endif

static void print_memory(const char* indent, const byte_t* bytes, const int nbytes, const int and_more);
static const char* phdr_type2str(const ElfW(Word) type);

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
	byte_t* filebin = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);

#else
	puts("\n*** target is MEMORY ***\n");

	const u_long at_base = getauxval(AT_BASE);
	const u_long at_phdr = getauxval(AT_PHDR);
	const u_long at_entry = getauxval(AT_ENTRY);

	printf("AT_SYSINFO_EHDR\t%p ('linux-vdso.so.1')\n", (void*)getauxval(AT_SYSINFO_EHDR));
	printf("AT_BASE\t%p ('/lib64/ld-linux-x86-64.so.2')\n", (void*)at_base);
	printf("AT_PHDR\t%p\n", (void*)at_phdr);
	printf("AT_ENTRY\t%p\n", (void*)at_entry);
#endif

#ifdef TFILE
	const ElfW(Ehdr)* ehdr = (ElfW(Ehdr)*)filebin;
	printf("Elf_Ehdr (0x0)\n");
#else
	const ElfW(Ehdr)* ehdr = (ElfW(Ehdr)*)at_base;
	printf("Elf_Ehdr (%p)\n", ehdr);
#endif

	puts("\te_ident");
	assert(ehdr->e_ident[EI_MAG0] == 0x7f);
	assert(ehdr->e_ident[EI_MAG1] == 'E');
	assert(ehdr->e_ident[EI_MAG2] == 'L');
	assert(ehdr->e_ident[EI_MAG3] == 'F');
	assert(ehdr->e_ident[EI_CLASS] == ELFCLASS64);
	assert(ehdr->e_ident[EI_DATA] == ELFDATA2LSB);
	assert(ehdr->e_ident[EI_VERSION] == EV_CURRENT);

	printf("\t\tEI_OSABI\t%d\n", ehdr->e_ident[EI_OSABI]);
	printf("\t\tEI_ABIVERSION\t%d\n", ehdr->e_ident[EI_ABIVERSION]);

	printf("\te_type\t%d\n", ehdr->e_type);
	assert(ehdr->e_machine == 62);
	assert(ehdr->e_version == 1);
	printf("\te_entry\t%p\n", (void*)ehdr->e_entry);
	printf("\te_phoff\t%lu\n", ehdr->e_phoff);
	printf("\te_shoff\t%lu (%p)\n", ehdr->e_shoff, (void*)ehdr->e_shoff);
	assert(ehdr->e_flags == 0);

	printf("\te_ehsize\t%u\n", ehdr->e_ehsize);
	assert(ehdr->e_ehsize == sizeof(ElfW(Ehdr)));
	printf("\te_phentsize\t%u\n", ehdr->e_phentsize);
	assert(ehdr->e_phentsize == sizeof(ElfW(Phdr)));
	printf("\te_phnum\t%u\n", ehdr->e_phnum);
	printf("\te_shentsize\t%u\n", ehdr->e_shentsize);
	assert(ehdr->e_shentsize == sizeof(ElfW(Shdr)));
	printf("\te_shnum\t%u\n", ehdr->e_shnum);
	printf("\te_shstrndx\t%u\n", ehdr->e_shstrndx);

#ifdef TFILE
	const ElfW(Phdr)* elf_phdrs = (ElfW(Phdr)*)&filebin[ehdr->e_phoff];
	printf("Elf_Phdr (%p)\n", (void*)ehdr->e_phoff);

/*
	for (int i=0; i<ehdr->e_phnum; i++)
	{
		printf("\tElf_Phdr[%d]\n", i);
		print_phdr_members("\t\t", &elf_phdrs[i]);
	}
*/
	print_phdrs(elf_phdrs, ehdr->e_phnum, filebin);

	//
	printf("Elf_Shdr (%p)\n", (void*)ehdr->e_shoff);

	print_shdrs(ehdr, (ElfW(Shdr)*)&filebin[ehdr->e_shoff], ehdr->e_shnum, filebin);

#else
	puts("Elf_Phdr");
	dl_iterate_phdr(phdr_callback, NULL);

#endif


#ifdef TMEM
	const void* v_entry = (void*)at_entry;
#endif


#ifdef TFILE
	munmap(filebin, st.st_size);
	close(fd);
#endif	

	return 0;
}

static void print_syms(const char* indent, const ElfW(Sym)* syms, const int start, const int nsyms, const char* strtab)
{
	for (int i=0; i<nsyms; i++)
	{
		const ElfW(Sym)* sym = &syms[start + i];

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

static void print_strtab(const char* indent, const char* pos);
static void print_relas(const char* indent, const ElfW(Rela)* relas, const int nrelas, const ElfW(Sym)* symtab, const char* strtab);

#ifdef TFILE
static void print_shdrs(const ElfW(Ehdr)* ehdr, const ElfW(Shdr)* shdrs, const ElfW(Half) shnum, const byte_t* filebin)
{
	const char* shstrtab = (char*)&filebin[shdrs[ehdr->e_shstrndx].sh_offset];

	const ElfW(Sym)* dynsym = NULL;
	const char* dynstrtab = NULL;

	for (int i=0; i<shnum; i++)
	{
		const ElfW(Shdr)* shdr = &shdrs[i];

		printf("\tElf_Shdr[%d]\n", i);

		printf("\t\tsh_name\t%u", shdr->sh_name);
		if (shstrtab)
		{
			printf(" '%s'", &shstrtab[shdr->sh_name]);
		}
		puts("");

		printf("\t\tsh_type\t%u (0x%x)\t'%s'\n",
			shdr->sh_type, shdr->sh_type, shdr_type2str(shdr->sh_type));

		printf("\t\tsh_flags\t0x%02lx", shdr->sh_flags);

		if (shdr->sh_flags)
		{
			printf(" (%c%c%c%c%c%c%c%c%c%c%c)",
				shdr->sh_flags & SHF_WRITE            ? 'W' : '_',
				shdr->sh_flags & SHF_ALLOC            ? 'A' : '_',
				shdr->sh_flags & SHF_EXECINSTR        ? 'E' : '_',
				shdr->sh_flags & SHF_MERGE            ? 'M' : '_',
				shdr->sh_flags & SHF_STRINGS          ? 'S' : '_',
				shdr->sh_flags & SHF_INFO_LINK        ? 'I' : '_',
				shdr->sh_flags & SHF_LINK_ORDER       ? 'L' : '_',
				shdr->sh_flags & SHF_OS_NONCONFORMING ? 'O' : '_',
				shdr->sh_flags & SHF_GROUP            ? 'G' : '_',
				shdr->sh_flags & SHF_TLS              ? 'T' : '_',
				shdr->sh_flags & SHF_MASKOS           ? 'm' : '_');
		}

		puts("");

		printf("\t\tsh_addr\t%lu (%p)\n", shdr->sh_addr, (void*)shdr->sh_addr);
		printf("\t\tsh_offset\t%lu (%p)\n", shdr->sh_offset, (void*)shdr->sh_offset);
		printf("\t\tsh_size\t%lu (0x%lx)\n", shdr->sh_size, shdr->sh_size);
		printf("\t\tsh_link\t%u\n", shdr->sh_link);
		printf("\t\tsh_info\t%u\n", shdr->sh_info);
		printf("\t\tsh_addralign\t%lu\n", shdr->sh_addralign);
		printf("\t\tsh_entsize\t%lu\n", shdr->sh_entsize);

		const void* filepos = &filebin[shdr->sh_offset];

		switch (shdr->sh_type)
		{
			case SHT_DYNAMIC:
			{
				print_dyns("\t\t\t", (ElfW(Dyn)*)filepos, filebin);
				break;
			}

			case SHT_SYMTAB:
			{
				const ElfW(Sym)* syms = (ElfW(Sym)*)filepos;
				const int nsyms = shdr->sh_size / shdr->sh_entsize;
				const char* strtab = (char*)&filebin[shdrs[shdr->sh_link].sh_offset];

				print_syms("\t\t\t", syms, 0, nsyms, strtab);

				break;
			}

			case SHT_DYNSYM:
			{
				const ElfW(Sym)* syms = (ElfW(Sym)*)filepos;
				const int nsyms = shdr->sh_size / shdr->sh_entsize;
				const char* strtab = (char*)&filebin[shdrs[shdr->sh_link].sh_offset];

				print_syms("\t\t\t", syms, 0, nsyms, strtab);

				dynsym = syms;
				dynstrtab = strtab;

				break;
			}

/*
			case SHT_DYNSTR:
			{
				break;
			}
*/

			case SHT_RELA:
			{
				const ElfW(Rela)* relas = (ElfW(Rela)*)filepos;

				assert(shdr->sh_entsize == sizeof(ElfW(Rela)));
				const int nrelas = shdr->sh_size / shdr->sh_entsize;

				print_relas("\t\t\t", relas, nrelas, dynsym, dynstrtab);

				break;
			}

			case SHT_INIT_ARRAY:
			case SHT_FINI_ARRAY:
			{
				for (int i=0; i<(shdr->sh_size/shdr->sh_entsize); i++)
				{
					const unsigned long offset = *((unsigned long*)(filepos + shdr->sh_entsize * i));

					printf("\t\t\t[%d]=%p", i, (void*)offset);
					print_memory("\t", (byte_t*)(filebin + offset), 16, 1);
				}

				break;
			}

			case SHT_NOTE:
			{
				print_note("\t\t\t", filepos, shdr->sh_size);
				break;
			}

			case SHT_STRTAB:
			{
				print_strtab("\t\t\t", filepos);
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

static void print_relas(const char* indent, const ElfW(Rela)* relas, const int nrelas, const ElfW(Sym)* symtab, const char* strtab)
{
	for (int i=0; i<nrelas; i++)
	{
		const ElfW(Rela)* rela = (ElfW(Rela)*)&relas[i];

		const int r_info_sym = ELF64_R_SYM(rela->r_info);

		printf("%sr_offset\t%p\n", indent, (void*)rela->r_offset);
		printf("%sr_info(sym)\t%d\n", indent, r_info_sym);

		if (symtab && strtab)
		{
			printf("%s\t\t'%s'\n", indent, &strtab[symtab[r_info_sym].st_name]);
		}

		printf("%sr_info(type)\t%lu\n", indent, ELF64_R_TYPE(rela->r_info));
		printf("%sr_addend\t%ld\n", indent, rela->r_addend);
	}
}

static void print_strtab(const char* indent, const char* pos)
{
	const char* start = pos;
	pos++;

	const char* last = NULL;

	int i;

	for (i=0; *pos; i++)
	{
		if (i < 20)
		{
			printf("%s\t%d: (%ld) '%s'\n", indent, i, pos - start, pos);
		}

		last = pos;
		pos = pos + strlen(pos) + 1;
	}

	if (i >= 20)
	{
		printf("%s\t\t...\n", indent);

		printf("%s\t%d: (%ld) '%s'\n", indent, i, last - start, last);
	}
}

static const char* dyn_tag2str(const ElfW(Xword) tag);
static Elf_Symndx lookup_sym_gnu(const char* indent, const uint32_t* hash32, const char* key);
static uint32_t new_hash_elf(const char* name);

#ifdef TFILE
	#define D_UN_VAL(ba, v) (v.d_val)
#else
	#define D_UN_VAL(ba, v) ((ba) + (v.d_val))
#endif

static void print_dyns(const char* indent, const ElfW(Dyn)* dyns, const byte_t* baseadr)
{
	char* indent1 = alloca(strlen(indent) + 2);
	strcpy(indent1, indent);
	strcat(indent1, &indent[strlen(indent) - 1]);

	char* indent2 = alloca(strlen(indent1) + 2);
	strcpy(indent2, indent1);
	strcat(indent2, &indent1[strlen(indent1) - 1]);

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
	const ElfW(Sym)* symtab = NULL;

	ElfW(Addr) hashtab_gnu = 0;
	ElfW(Addr) hashtab_elf = 0;

	const ElfW(Rela)* rela = NULL;
	ElfW(Xword) relasz = 0;
	ElfW(Xword) relaent = 0;

	for (int idx=0; dyns[idx].d_un.d_val != DT_NULL; idx++)
	{
		const ElfW(Dyn)* dyn = &dyns[idx];

		printf("%sElf_Dyn[%d]\n", indent, idx);
		printf("%s\td_tag\t%ld (0x%p) '%s'\n",
			indent, dyn->d_tag, (void*)dyn->d_tag, dyn_tag2str(dyn->d_tag));

		switch (dyn->d_tag)
		{
			case DT_NEEDED:
			{
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
				printf("%s\t%p\n", indent, (void*)dyn->d_un.d_ptr);

				print_strtab(indent1, (char*)strtab);

				break;
			}

			case DT_STRSZ:
			{
				printf("%s\t%lu\n", indent, dyn->d_un.d_val);

				break;
			}

			case DT_INIT:
			{
				printf("%s\t%p (%p)\n",
					indent, (void*)dyn->d_un.d_ptr, (void*)D_UN_VAL(baseadr, dyn->d_un));

				print_memory(indent1, (byte_t*)(baseadr + dyn->d_un.d_val), 16, 1);

				break;
			}

			case DT_FINI:
			{
				printf("%s\t%p (%p)\n",
					indent, (void*)dyn->d_un.d_ptr, (void*)D_UN_VAL(baseadr, dyn->d_un));

				print_memory(indent1, baseadr + dyn->d_un.d_val, 16, 1);

				break;
			}

			case DT_INIT_ARRAY:
			{
#ifdef TMEM
//#ifdef TFILE
//				init_array = baseadr + dyn->d_un.d_val;
//#else
				init_array = dyn->d_un.d_ptr;
#endif

				printf("%s\t%p (%p)\n",
					indent, (void*)dyn->d_un.d_ptr, (void*)D_UN_VAL(baseadr, dyn->d_un));

				break;
			}

			case DT_FINI_ARRAY:
			{
#ifdef TMEM
//#ifdef TFILE
//				fini_array = baseadr + dyn->d_un.d_val;
//#endif
				fini_array = dyn->d_un.d_ptr;
#endif

				printf("%s\t%p(%p)\n",
					indent, (void*)dyn->d_un.d_ptr, (void*)(baseadr + dyn->d_un.d_ptr));

				break;
			}

			case DT_INIT_ARRAYSZ:
			{
				printf("%s\t%lu\n", indent, dyn->d_un.d_val);

				if (init_array)
				{
					const ElfW(Addr)* arr = (ElfW(Addr)*)(baseadr + init_array);

					for (int i=0; i<(dyn->d_un.d_val/sizeof(ElfW(Addr))); i++)
					{
						printf("%s\t[%d]=%p\n", indent, i, (void*)arr[i]);
						print_memory(indent1, (byte_t*)arr[i], 16, 1);
					}
				}

				break;
			}

			case DT_FINI_ARRAYSZ:
			{
				printf("%s\t%lu\n", indent, dyn->d_un.d_val);

				if (fini_array)
				{
					const ElfW(Addr)* arr = (ElfW(Addr)*)(baseadr + fini_array);

					for (int i=0; i<(dyn->d_un.d_val/sizeof(ElfW(Addr))); i++)
					{
						printf("%s\t[%d]=%p\n", indent, i, (void*)arr[i]);
						print_memory(indent1, (byte_t*)arr[i], 16, 1);
					}
				}

				break;
			}

			case DT_HASH:
			{
				// https://github.com/robgjansen/elf-loader/blob/master/vdl-lookup.c#L118
				// https://flapenguin.me/elf-dt-hash

#ifdef TFILE
				hashtab_elf = (ElfW(Addr))(baseadr + dyn->d_un.d_ptr);
#else
				hashtab_elf = (ElfW(Addr))dyn->d_un.d_ptr;
#endif

				printf("%s\t%p\n", indent, (void*)hashtab_elf);
				print_memory(indent1, (byte_t*)hashtab_elf, 16, 1);

				break;
			}

			case DT_GNU_HASH:
			{
				// https://blogs.oracle.com/solaris/post/gnu-hash-elf-sections
				// https://chowdera.com/2021/06/20210617215010995Q.html

#ifdef TFILE
				hashtab_gnu = (ElfW(Addr))(baseadr + dyn->d_un.d_ptr);
#else
				hashtab_gnu = (ElfW(Addr))dyn->d_un.d_ptr;
#endif

				printf("%s\t%p\n", indent, (void*)hashtab_gnu);
				print_memory(indent1, (byte_t*)hashtab_gnu, 16, 1);

				break;
			}

			case DT_SYMTAB:
			{
#ifdef TFILE
				symtab = (ElfW(Sym)*)(baseadr + dyn->d_un.d_val);
#else
				symtab = (ElfW(Sym)*)dyn->d_un.d_ptr;
#endif

				printf("%s\t%p\n", indent, (void*)symtab);

				if (!strtab)
					break;

				print_syms(indent1, symtab, 0, 3, strtab);
				printf("%s...\n", indent1);
				printf("%s...\n", indent1);

				const char* lookup_name = "realloc";

				if (hashtab_gnu)
				{
					printf("%s((gnu TEST S)) lookup('%s')\n", indent1, lookup_name);

					const Elf_Symndx symidx = lookup_sym_gnu(
						indent2, (uint32_t*)hashtab_gnu, lookup_name);

					printf("%s((gnu RESULT)) =>%u\n", indent1, symidx);
					if (symidx)
					{
						print_syms(indent2, symtab, symidx, 1, strtab);
					}

					printf("%s((gnu TEST E)) lookup('%s')\n", indent1, lookup_name);
				}

				if (hashtab_elf)
				{
					//
					// https://docs.oracle.com/cd/E26924_01/html/E25909/chapter6-48031.html#scrolltoc
					// https://flapenguin.me/elf-dt-hash
					//
					printf("%s((elf TEST S)) lookup('%s')\n", indent1, lookup_name);

					const uint32_t hash = new_hash_elf(lookup_name);
					printf("%shash=%u (%x)\n", indent2, hash, hash);

					const uint32_t* hashtab = (uint32_t*)hashtab_elf;
					const uint32_t nbucket = hashtab[0];
					const uint32_t nchain = hashtab[1];
					const uint32_t* bucket = &hashtab[2];
					const uint32_t* chain = &bucket[nbucket];

					printf("%snbuckets=%u\n", indent2, nbucket);
					printf("%snchain=%u\n", indent2, nchain);

					Elf_Symndx symidx = SHN_UNDEF;

					for (uint32_t i = bucket[hash % nbucket]; i; i = chain[i])
					{
						if (strcmp(lookup_name, strtab + symtab[i].st_name) == 0)
						{
							symidx = i;
							break;
						}
					}

					printf("%s((elf RESULT)) =>%u\n", indent1, symidx);
					if (symidx)
					{
						print_syms(indent2, symtab, symidx, 1, strtab);
					}

					printf("%s((elf TEST E)) lookup('%s')\n", indent1, lookup_name);
				}

				break;
			}

			case DT_SYMENT:
			{
				printf("%s\t%lu:%lu\n", indent, dyn->d_un.d_val, sizeof(Elf64_Sym));

				break;
			}

			case DT_RELA:
			{
				printf("%s\t%p\n", indent, (void*)dyn->d_un.d_ptr);

				rela = (ElfW(Rela)*)dyn->d_un.d_ptr;

				break;
			}

			case DT_RELASZ:
			{
				printf("%s\t%lu\n", indent, dyn->d_un.d_val);

				relasz = dyn->d_un.d_val;

				break;
			}

			case DT_RELAENT:
			{
				printf("%s\t%lu\n", indent, dyn->d_un.d_val);

				relaent = dyn->d_un.d_val;

				const int nrelas = relasz / relaent;

				print_relas("\t\t\t\t\t", rela, nrelas, symtab, strtab);

				break;
			}

			default:
			{
				printf("%sd_un.d_val=%lu (%p)\n", indent1, dyn->d_un.d_val, (void*)dyn->d_un.d_ptr);
				break;
			}
		}
	}
}

#define MIN(a, b) ((a) < (b) ? (a) : (b))

static void print_phdrs(const ElfW(Phdr)* phdrs, const int nphdrs, const byte_t* baseadr)
{
	for (int j = 0; j < nphdrs; j++)
	{
		const ElfW(Phdr)* phdr = &phdrs[j];
		printf("\tElf_Phdr[%d]\n", j);

#ifdef TFILE
		const byte_t* datapos = (byte_t*)(baseadr + phdr->p_offset);
#else
		const byte_t* datapos = (byte_t*)(baseadr + phdr->p_vaddr);
#endif
		print_phdr_members("\t\t", phdr);

#ifdef TMEM
		printf("\t\t\t* base=%p\n", baseadr);
		printf("\t\t\t* phdr=%p\n", phdr);

		if (phdr->p_filesz)
		{
			printf("\t\t\t* data=%p\n", datapos);
		}
#endif

		switch (phdr->p_type)
		{
			case PT_DYNAMIC:
			{
				print_dyns("\t\t\t", (ElfW(Dyn)*)datapos, baseadr);

				break;
			}

			case PT_INTERP:
			{
				printf("\t\t\t%s\n", (char*)datapos);
				break;
			}

			case PT_PHDR:
			{
				print_phdr_members("\t\t\t", (ElfW(Phdr)*)datapos);
				break;
			}

			case PT_LOAD:
			{
				print_memory("\t\t\t", datapos, MIN(16, phdr->p_memsz), 1);
				break;
			}

			case PT_NOTE:
			{
				// https://docs.oracle.com/cd/E38900_01/html/E38860/chapter6-18048.html#scrolltoc

				print_note("\t\t\t", datapos, phdr->p_filesz);

				break;
			}
		}
	}
}

static void print_note(const char* indent, const void* datapos, const ElfW(Xword) p_filesz)
{
	const void* next = datapos;
	const int ALIGN_SIZE = 4;

	do
	{
		const uint32_t* namesz = next;
		const uint32_t* descsz = namesz + 1;
		const uint32_t* type = descsz + 1;

		printf("%snamesz\t%u\n", indent, *namesz);
		printf("%sdescsz\t%u\n", indent, *descsz);

		printf("%stype\t%u\n", indent, *type);

		const char* name = (char*)(type + 1);

		if (*namesz)
		{
			printf("%sname\t'%s'\n", indent, name);

			//const int skip = ((*namesz / 4) + (*namesz % 4 > 0 ? 1 : 0)) * 4;
			//const int skip = ( ( ( *namesz + (ALIGN_SIZE - 1) ) >> 6 ) & 0177 ) * ALIGN_SIZE;
			const int skip = *namesz + (ALIGN_SIZE - 1) & ~(ALIGN_SIZE - 1);
			printf("%sn-skip\t%d\n", indent, skip);

			name += skip;
		}

		const byte_t* desc = (byte_t*)name;

		if (*descsz)
		{
			printf("%sdesc", indent);
			print_memory("\t", desc, MIN(*descsz, 16), *descsz <= 16 ? 0 : 1);

			//const int skip = ((*descsz / 4) + (*descsz % 4 > 0 ? 1 : 0)) * 4;
			//const int skip = ( ( ( *descsz + (ALIGN_SIZE - 1) ) >> 6 ) & 0177 ) * ALIGN_SIZE;
			const int skip = *descsz + (ALIGN_SIZE - 1) & ~(ALIGN_SIZE - 1);
			printf("%sd-skip\t%d\n", indent, skip);

			desc += skip;
		}

		next = desc;

		//printf("\t\toffset\t%ld\n", next - (void*)datapos);
	}
	while (next - datapos < p_filesz);
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

	print_phdrs(info->dlpi_phdr, info->dlpi_phnum, (byte_t*)info->dlpi_addr);


	return 0;
}
#endif

static void print_phdr_members(const char* indent, const ElfW(Phdr)* phdr)
{
	printf("%sp_type\t0x%x\t'%s'\n", indent, phdr->p_type, phdr_type2str(phdr->p_type));
	printf("%sp_offset\t%lu (0x%lx)\n", indent, phdr->p_offset, phdr->p_offset);
	printf("%sp_vaddr\t%lu (%p)\n", indent, phdr->p_vaddr, (void*)phdr->p_vaddr);
	printf("%sp_paddr\t%lu (%p)\n", indent, phdr->p_paddr, (void*)phdr->p_paddr);
	printf("%sp_filesz\t%lu\n", indent, phdr->p_filesz);
	printf("%sp_memsz\t%lu\n", indent, phdr->p_memsz);
	printf("%sp_flags\t0x%x (%c%c%c%c)\n", indent, phdr->p_flags,
		phdr->p_flags & PF_X ? 'X' : '_',
		phdr->p_flags & PF_W ? 'W' : '_',
		phdr->p_flags & PF_R ? 'R' : '_',
		phdr->p_flags & PF_MASKPROC ? 'M' : '_'
	);
	printf("%sp_align\t%lu\n", indent, phdr->p_align);
}

static void print_memory(const char* indent, const byte_t* bytes, const int nbytes, const int and_more)
{
	printf("%s{", indent);

	for (int i=0; i<nbytes; i++)
	{
		printf("%s%02x ", (i % 4 == 0) ? " " : "", bytes[i]);
	}

	if (and_more)
	{
		printf("...");
	}

	puts("}");
}

//
// https://chowdera.com/2021/06/20210617215010995Q.html
// https://sources.debian.org/src/glibc/2.31-13%2Bdeb11u3/elf/dl-lookup.c/#L578-L585
// https://sources.debian.org/src/glibc/2.31-13%2Bdeb11u3/elf/dl-lookup.c/#L411-L447
//
static uint32_t new_hash_gnu(const char *s)
{
	uint32_t h = 5381;

	for (unsigned char c = *s; c != '\0'; c = *++s)
		h = h * 33 + c;

	return h & 0xffffffff;
}

//
// https://flapenguin.me/elf-dt-hash
// https://github.com/unikraft/lib-libelf/blob/staging/elf_hash.c
//
static uint32_t new_hash_elf(const char* name)
{
	uint32_t h = 0, g;

	for (; *name; name++)
	{
		h = (h << 4) + *name;

		//if (g = h & 0xf0000000)
		g = h & 0xf0000000;
		if (g)
			h ^= g >> 24;

		h &= ~g;
	}

	return h;
}


static Elf_Symndx lookup_sym_gnu(const char* indent, const uint32_t* hash32, const char* key)
{
	const uint32_t l_nbuckets = *hash32++;
	const uint32_t symbias = *hash32++;
	const uint32_t bitmask_nwords = *hash32++;
	assert ((bitmask_nwords & (bitmask_nwords - 1)) == 0);
	const uint32_t l_gnu_bitmask_idxbits = bitmask_nwords - 1;
	const uint32_t l_gnu_shift = *hash32++;

	const ElfW(Addr)* l_gnu_bitmask = (ElfW(Addr)*)hash32;
	hash32 += __ELF_NATIVE_CLASS / 32 * bitmask_nwords;

	const uint32_t* l_gnu_buckets = hash32;
	hash32 += l_nbuckets;
	const uint32_t* l_gnu_chain_zero = hash32 - symbias;

	//
	printf("%sl_nbuckets=%u\n", indent, l_nbuckets);
	printf("%ssymbias=%u\n", indent, symbias);
	printf("%sbitmask_nwords=%u\n", indent, bitmask_nwords);
	printf("%sl_gnu_bitmask_idxbits=%u\n", indent, l_gnu_bitmask_idxbits);
	printf("%sl_gnu_shift=%u\n", indent, l_gnu_shift);

	//
	const uint32_t new_hash = new_hash_gnu(key);
	printf("%snew_hash=%x\n", indent, new_hash);

	//
	const ElfW(Addr)* bitmask = l_gnu_bitmask;
	const ElfW(Addr) bitmask_word = bitmask[(new_hash / __ELF_NATIVE_CLASS) & l_gnu_bitmask_idxbits];

	printf("%sbitmask_word=0x%lx\n", indent, bitmask_word);

	//
	const unsigned int hashbit1 = new_hash & (__ELF_NATIVE_CLASS - 1);
	const unsigned int hashbit2 = ((new_hash >> l_gnu_shift) & (__ELF_NATIVE_CLASS - 1));

	printf("%shashbit1=%u, hashbit2=%u\n", indent, hashbit1, hashbit2);

	//
	//if (__glibc_unlikely((bitmask_word >> hashbit1) & (bitmask_word >> hashbit2) & 1))
	if ((bitmask_word >> hashbit1) & (bitmask_word >> hashbit2) & 1)
	{
		printf("%s[x]=%u\n", indent, new_hash % l_nbuckets);

		const Elf32_Word bucket = l_gnu_buckets[new_hash % l_nbuckets];
		printf("%sbucket=%u\n", indent, bucket);

		if (bucket != 0)
		{
			const Elf32_Word* hasharr = &l_gnu_chain_zero[bucket];

			do
			{
				printf("%s*hasharr=%u new_hash=%u\n", indent, *hasharr, new_hash);

				if (((*hasharr ^ new_hash) >> 1) == 0)
				{
					const Elf_Symndx symidx = hasharr - l_gnu_chain_zero;
					printf("%ssymidx=%x\n", indent, symidx);

					return symidx;
				}
			}
			while ((*hasharr++ & 1u) == 0);
		}
	}

	printf("%sdone.\n", indent);

	return SHN_UNDEF;
}

static const char* phdr_type2str(const ElfW(Word) type)
{
	switch (type)
	{
		case PT_NULL:			return "PT_NULL";
		case PT_LOAD:			return "PT_LOAD";
		case PT_DYNAMIC:		return "PT_DYNAMIC";
		case PT_INTERP:			return "PT_INTERP";
		case PT_NOTE:			return "PT_NOTE";
		case PT_SHLIB:			return "PT_SHLIB";
		case PT_PHDR:			return "PT_PHDR";
		case PT_TLS:			return "PT_TLS";
		case PT_LOOS:			return "PT_LOOS";
		case PT_HIOS:			return "PT_HIOS";
		case PT_LOPROC:			return "PT_LOPROC";
		case PT_HIPROC:			return "PT_HIPROC";
		case PT_GNU_EH_FRAME:	return "PT_GNU_EH_FRAME";
		case PT_GNU_STACK:		return "PT_GNU_STACK";
		case PT_GNU_RELRO:		return "PT_GNU_RELRO";
	}

	return "***";
}

#ifdef TFILE
static const char* shdr_type2str(const ElfW(Word) type)
{
	switch (type)
	{
		case SHT_NULL:			return "SHT_NULL";
		case SHT_PROGBITS:		return "SHT_PROGBITS";
		case SHT_SYMTAB:		return "SHT_SYMTAB";
		case SHT_STRTAB:		return "SHT_STRTAB";
		case SHT_RELA:			return "SHT_RELA";
		case SHT_HASH:			return "SHT_HASH";
		case SHT_DYNAMIC:		return "SHT_DYNAMIC";
		case SHT_NOTE:			return "SHT_NOTE";
		case SHT_NOBITS:		return "SHT_NOBITS";
		case SHT_REL:			return "SHT_REL";
		case SHT_SHLIB:			return "SHT_SHLIB";
		case SHT_DYNSYM:		return "SHT_DYNSYM";
		case SHT_INIT_ARRAY:	return "SHT_INIT_ARRAY";
		case SHT_FINI_ARRAY:	return "SHT_FINI_ARRAY";
		case SHT_PREINIT_ARRAY:	return "SHT_PREINIT_ARRAY";
		case SHT_GROUP:			return "SHT_GROUP";
		case SHT_SYMTAB_SHNDX:	return "SHT_SYMTAB_SHNDX";
		case SHT_NUM:			return "SHT_NUM";
		case SHT_LOPROC:		return "SHT_LOPROC";
		case SHT_HIPROC:		return "SHT_HIPROC";
		case SHT_LOUSER:		return "SHT_LOUSER";
		case SHT_HIUSER:		return "SHT_HIUSER";
		case SHT_GNU_HASH:		return "SHT_GNU_HASH";
		case SHT_GNU_versym:	return "SHT_GNU_versym";
		case SHT_GNU_verneed:	return "SHT_GNU_verneed";
	}

	return "***";
}
#endif

static const char* dyn_tag2str(const ElfW(Xword) tag)
{
	switch (tag)
	{
		case DT_NULL: return "DT_NULL";
		case DT_NEEDED: return "DT_NEEDED";
		case DT_PLTRELSZ: return "DT_PLTRELSZ";
		case DT_PLTGOT: return "DT_PLTGOT";
		case DT_HASH: return "DT_HASH";
		case DT_STRTAB: return "DT_STRTAB";
		case DT_SYMTAB: return "DT_SYMTAB";
		case DT_RELA: return "DT_RELA";
		case DT_RELASZ: return "DT_RELASZ";
		case DT_RELAENT: return "DT_RELAENT";
		case DT_STRSZ: return "DT_STRSZ";
		case DT_SYMENT: return "DT_SYMENT";
		case DT_INIT: return "DT_INIT";
		case DT_FINI: return "DT_FINI";
		case DT_SONAME: return "DT_SONAME";
		case DT_SYMBOLIC: return "DT_SYMBOLIC";
		case DT_REL: return "DT_REL";
		case DT_RELSZ: return "DT_RELSZ";
		case DT_RELENT: return "DT_RELENT";
		case DT_PLTREL: return "DT_PLTREL";
		case DT_DEBUG: return "DT_DEBUG";
		case DT_TEXTREL: return "DT_TEXTREL";
		case DT_JMPREL: return "DT_JMPREL";
		case DT_BIND_NOW: return "DT_BIND_NOW";
		case DT_INIT_ARRAY: return "DT_INIT_ARRAY";
		case DT_FINI_ARRAY: return "DT_FINI_ARRAY";
		case DT_INIT_ARRAYSZ: return "DT_INIT_ARRAYSZ";
		case DT_FINI_ARRAYSZ: return "DT_FINI_ARRAYSZ";
		case DT_RUNPATH: return "DT_RUNPATH";
		case DT_FLAGS: return "DT_FLAGS";
		//case DT_ENCODING: return "DT_ENCODING";
		case DT_PREINIT_ARRAY: return "DT_PREINIT_ARRAY";
		case DT_PREINIT_ARRAYSZ: return "DT_PREINIT_ARRAYSZ";
		case DT_SYMTAB_SHNDX: return "DT_SYMTAB_SHNDX";
		case DT_NUM: return "DT_NUM";
		case DT_LOOS: return "DT_LOOS";
		case DT_HIOS: return "DT_HIOS";
		case DT_LOPROC: return "DT_LOPROC";
		case DT_HIPROC: return "DT_HIPROC";
		case DT_PROCNUM: return "DT_PROCNUM";
		case DT_VALRNGLO: return "DT_VALRNGLO";
		case DT_GNU_PRELINKED: return "DT_GNU_PRELINKED";
		case DT_GNU_CONFLICTSZ: return "DT_GNU_CONFLICTSZ";
		case DT_GNU_LIBLISTSZ: return "DT_GNU_LIBLISTSZ";
		case DT_CHECKSUM: return "DT_CHECKSUM";
		case DT_PLTPADSZ: return "DT_PLTPADSZ";
		case DT_MOVEENT: return "DT_MOVEENT";
		case DT_MOVESZ: return "DT_MOVESZ";
		case DT_POSFLAG_1: return "DT_POSFLAG_1";
		case DT_SYMINENT: return "DT_SYMINENT";
		//case DT_VALRNGHI: return "DT_VALRNGHI";
		//case DT_VALNUM: return "DT_VALNUM";
		//case DT_ADDRRNGLO: return "DT_ADDRRNGLO";
		case DT_GNU_HASH: return "DT_GNU_HASH";
		case DT_TLSDESC_PLT: return "DT_TLSDESC_PLT";
		case DT_TLSDESC_GOT: return "DT_TLSDESC_GOT";
		case DT_GNU_CONFLICT: return "DT_GNU_CONFLICT";
		case DT_GNU_LIBLIST: return "DT_GNU_LIBLIST";
		case DT_CONFIG: return "DT_CONFIG";
		case DT_DEPAUDIT: return "DT_DEPAUDIT";
		case DT_AUDIT: return "DT_AUDIT";
		case DT_PLTPAD: return "DT_PLTPAD";
		case DT_MOVETAB: return "DT_MOVETAB";
		case DT_SYMINFO: return "DT_SYMINFO";
		//case DT_ADDRRNGHI: return "DT_ADDRRNGHI";
		//case DT_ADDRNUM: return "DT_ADDRNUM";
		case DT_VERSYM: return "DT_VERSYM";
		case DT_RELACOUNT: return "DT_RELACOUNT";
		case DT_RELCOUNT: return "DT_RELCOUNT";
		case DT_FLAGS_1: return "DT_FLAGS_1";
		case DT_VERDEF: return "DT_VERDEF";
		case DT_VERDEFNUM: return "DT_VERDEFNUM";
		case DT_VERNEED: return "DT_VERNEED";
		case DT_VERNEEDNUM: return "DT_VERNEEDNUM";
		//case DT_VERSIONTAGNUM: return "DT_VERSIONTAGNUM";
		case DT_AUXILIARY: return "DT_AUXILIARY";
		//case DT_FILTER: return "DT_FILTER";
		//case DT_EXTRANUM: return "DT_EXTRANUM";
	}

	return "***";
}

