#!/bin/bash

cd $(dirname $(readlink -f "${BASH_SOURCE:-$0}"))

set -ex

ptype=${1:-TFILE}
#ptype=${1:-TMEM}

gccopts=''
gccopts="${gccopts} -D${ptype} -Wformat -Wformat-signedness"
gccopts="${gccopts} -Wall"
#gccopts="${gccopts} -Wextra"

# https://d2v.hatenablog.com/entry/2021/06/24/003258
# set X to PT_GNU_STACK.p_flags
#gccopts="${gccopts} -z execstack"

clear

#gcc -ggdb -O0 -c elf-dt-gnu-hash.c

gcc ${gccopts} -ggdb -O0 -c src.c
gcc ${gccopts} -E src.c > src.pc
#gcc ${gccopts} -o exe src.o elf-dt-gnu-hash.o
gcc ${gccopts} -o exe src.o

ulimit -c unlimited
./exe

