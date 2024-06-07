# mps-fuzz-tool
MPS-Fuzz is a fine-grain coverage fuzzer. 

Abstract of MPS-Fuzz:
MPS-Fuzz proposes the structure of a basic block unit with multiple predecessors and successors (referred to as MPS). 
Then, a fine-grained coverage method called MPS-Fuzz is designed based on the MPS structure. 
In this approach, it is convenient to exclude basic blocks involving loop structures when determining MPS units, which helps reduce seed homogeneity.
Additionally, we introduce an additional bitmap to record the coverage status of MPS units, 
ensuring that the collision rate of the edge bitmap does not increase. 
Moreover, these additional operations do not incur excessively high additional time overhead.
More details could be found in our paper. The paper will be uploaded later. 

MPS-Fuzz is implemented based on AFL, and therefore, its usage is similar to that of AFL. 
First, the compilation process MPS-Fuzz is as follows:
$ cd /youpath/MPS-Fuzz && make
$ cd ./llvm_mode && make
If you encounter the following error while compiling afl-clang-fast, do not worry. 
This is due to modifications in the instrumentation that cause issues with the comparison validation in AFL's native test-instru.c, but it does not affect usage.
****
[*] Testing the CC wrapper and instrumentation output...
unset AFL_USE_ASAN AFL_USE_MSAN; AFL_QUIET=1 AFL_INST_RATIO=100 AFL_PATH=. ./afl-gcc -O3 -funroll-loops -Wall -D_FORTIFY_SOURCE=2 -g -Wno-pointer-sign -DAFL_PATH=\"/usr/local/lib/afl\" -DDOC_PATH=\"/usr/local/share/doc/afl\" -DBIN_PATH=\"/usr/local/bin\" test-instr.c -o test-instr -ldl
echo 0 | ./afl-showmap -m none -q -o .test-instr0 ./test-instr
make: *** [Makefile:92: test_build] Error 2
****

Then, the compilation process for the program under test is as follows:
$ CC=/path/to/afl/afl-gcc ./configure
$ make clean all



fuzzing command:
/yourpath/MPS-Fuzz/afl-fuzz -m none [-d] -i /in -o /out target [-some option for target] @@   
([*] means optional)
