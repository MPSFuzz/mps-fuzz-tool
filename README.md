## Introduction

MPS-Fuzz is a fine-grain coverage fuzzer.

MPS-Fuzz proposes the structure of a basic block unit with multiple predecessors and successors (referred to as MPS).  Then, a fine-grained coverage method called MPS-Fuzz is designed based on the MPS structure.  In this approach, it is convenient to exclude basic blocks involving loop structures when determining MPS units, which helps reduce seed homogeneity.  Additionally, we introduce an additional bitmap to record the coverage status of MPS units, ensuring that the collision rate of the edge bitmap does not increase.  Moreover, these additional operations do not incur excessively high additional time overhead.  More details could be found in our paper. The paper will be uploaded later.

* Here we have released the source code of the two methods: MPS-Fuzz, and the Havoc-mab + MPS

## Environment

- We test the tool on Ubuntu 18.04/20.04, LLVM 10.0-12.0
- If llvm >=14, the code of afl-llvm-pass.so.cc about loop structure would not be supported. 
  
  

## Environment variable: MPS-SIZE

* The granularity of MPS-Fuzz could be selected by the variable $AFL_LLVM_MPS_SIZE. The same way as N-gram in AFL++

* Before compling
  
  ```shell
  export AFL_LLVM_MPS_SIZE=3
  ```
  
  

* The $AFL_LLVM_MPS_SIZE could be selected from 2 to 8, and recommonded 3.  Default is 3 too.

## Usage

* The usage is almost the same as AFL.  Both MPS-Fuzz and the combination of Havoc-mab with MPS are used in the same manner.

* Firstly, complie the mps-fuzz-tool
  
  ```shell
  cd /you-path/mps-fuzz  && make
  cd ./llvm_mode && make
  ```

* Secondly, complie your target
  
  ```shell
  export CC=/you-path/mps-fuzz/afl-clang-fast
  export CXX= /you-path/mps-fuzz/afl-clang-fast++
  export AFL_LLVM_MPS_SIZE=3 
  //Don't forget it, or you will set it 3 as default
  
  ./configure && make    // make your target 
  ```

* Run the fuzz loop
  
  ```shell
  /you-path/mps-fuzz/afl-fuzz -d -i $FUZZ_IN -o $FUZZ_OUT -- ./your-targets @@
  ```
  
## 0-day found by MPS-Fuzz
* A null pointer reference on gpac2.5.0
state: confirmed and fixed; issue number: #3340; url: https://github.com/gpac/gpac/issues/3340 (the issue has been closed)

