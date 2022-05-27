#!/bin/bash

cd $(dirname $(readlink -f "${BASH_SOURCE:-$0}"))

set -ex

#ptype=${1:-TFILE}
ptype=${1:-TMEM}

gccopts=''
gccopts="${gccopts} -ggdb -O0"
gccopts="${gccopts} -D${ptype} -Wformat -Wformat-signedness"
gccopts="${gccopts} -Wall"
#gccopts="${gccopts} -Wextra"

# https://d2v.hatenablog.com/entry/2021/06/24/003258
# set X to PT_GNU_STACK.p_flags
#gccopts="${gccopts} -z execstack"

clear

#gcc -ggdb -O0 -c elf-dt-gnu-hash.c

gcc ${gccopts} -E dll.c > dll.pc
gcc ${gccopts} -shared -fPIC -o libdll.so dll.c

gcc ${gccopts} -c main.c
gcc ${gccopts} -E main.c > main.pc

gcc ${gccopts} -o main.exe main.o -L. -ldll
#gcc ${gccopts} -o main.exe main.o

ulimit -c unlimited
LD_LIBRARY_PATH=. ./main.exe

exit 0
