set step-mode on
set confirm off
#set pagination off
set disable-randomization off
set env LD_LIBRARY_PATH .
set env LD_AUDIT ./audit.so
set output-radix 16

set backtrace past-entry
set backtrace past-main
set verbose on

directory ../elf

tui enable

layout asm
layout src
layout split

# https://stackoverflow.com/questions/38803783/how-to-automatically-refresh-gdb-in-tui-mode
define hook-next
  refresh
end

#define dsx
#  x/32x $sp
#end
#define dsb
#  x/32b $sp
#end

#break *main
#run
#display /d $eax
#display /d $ebx
#display /d $ebp
#display /4i $pc

alias -a dsb = x/32b $sp
alias -a dsx = x/32x $sp

start
