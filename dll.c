#include <stdio.h>

__attribute__ ((constructor)) static void dll_construct()
{
	puts("dll_construct");
}

__attribute__ ((destructor)) static void dll_destruct()
{
	puts("dll_destruct");
}

void dll_main()
{
	printf("dll_main\t%p\n", dll_main);
}

// EOF

