/*
  Copyright 2015 Google LLC All rights reserved.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at:

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

/*
   american fuzzy lop - LLVM-mode instrumentation pass
   ---------------------------------------------------

   Written by Laszlo Szekeres <lszekeres@google.com> and
              Michal Zalewski <lcamtuf@google.com>

   LLVM integration design comes from Laszlo Szekeres. C bits copied-and-pasted
   from afl-as.c are Michal's fault.

   This library is plugged into LLVM when invoking clang through afl-clang-fast.
   It tells the compiler to add code roughly equivalent to the bits discussed
   in ../afl-as.h.
*/

#define AFL_LLVM_PASS

#include "../config.h"
#include "../debug.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <unordered_map>
#include <list>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <vector>
#include <array>
#include <map>
#include <set>


#include "llvm/Config/llvm-config.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/MDBuilder.h"
#include "llvm/Support/Debug.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Analysis/CFGPrinter.h"
#include "afl-llvm-common.h"

#include "llvm/IR/CFG.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Analysis/LoopInfo.h"

#if defined(LLVM34)
#include "llvm/DebugInfo.h"
#else
#include "llvm/IR/DebugInfo.h"
#endif

using namespace std;
using namespace llvm;

namespace {

  class AFLCoverage : public ModulePass {

    public:

      static char ID;
      AFLCoverage() : ModulePass(ID) { }

      bool runOnModule(Module &M) override;

      void getAnalysisUsage(llvm::AnalysisUsage &AU) const override {
        // SET 'LoopInfoWrapperPass' required
        AU.addRequired<LoopInfoWrapperPass>();
      } 


    protected:
      fstream file;
      uint32_t    mps_size = 0;                                                         // by FXM
      u32 MPS_SIZE_MAX = 8;
      

      int deter_multi_input(BasicBlock &BB1){
        BasicBlock *bb1 = &BB1;
        
        int numPredecessors = std::distance(pred_begin(bb1), pred_end(bb1));
        if (numPredecessors > 1) {return 1;}
        return 0;
      }
      
      int deter_multi_output(BasicBlock &BB1){
        BasicBlock *bb1 = &BB1;
        unsigned numSuccessors = bb1->getTerminator()->getNumSuccessors();
        if (numSuccessors > 1)  {return 1;}
        return 0;
      }

  };

}


char AFLCoverage::ID = 0;

static bool isBlacklisted(const Function *F) {
  static const SmallVector<std::string, 8> Blacklist = {
    "asan.",
    "llvm.",
    "sancov.",
    "__ubsan_handle_",
    "free",
    "malloc",
    "calloc",
    "realloc"
  };

  for (auto const &BlacklistFunc : Blacklist) {
    if (F->getName().startswith(BlacklistFunc)) {
      return true;
    }
  }

  return false;
}


bool AFLCoverage::runOnModule(Module &M) {

  LLVMContext &C = M.getContext();

  IntegerType *Int8Ty  = IntegerType::getInt8Ty(C);
  IntegerType *Int32Ty = IntegerType::getInt32Ty(C);

  /* Show a banner */

  char be_quiet = 0;

  if (isatty(2) && !getenv("AFL_QUIET")) {

    SAYF(cCYA "afl-llvm-pass " cBRI VERSION cRST " by <lszekeres@google.com>\n");

  } else be_quiet = 1;

  /* Decide instrumentation ratio */

  char* inst_ratio_str = getenv("AFL_INST_RATIO");
  unsigned int inst_ratio = 100;

  if (inst_ratio_str) {

    if (sscanf(inst_ratio_str, "%u", &inst_ratio) != 1 || !inst_ratio ||
        inst_ratio > 100)
      FATAL("Bad value of AFL_INST_RATIO (must be between 1 and 100)");

  }

  /* Get globals for the SHM region and the previous location. Note that
     __afl_prev_loc is thread-local. */

  GlobalVariable *AFLMapPtr =
      new GlobalVariable(M, PointerType::get(Int8Ty, 0), false,
                         GlobalValue::ExternalLinkage, 0, "__afl_area_ptr");
                      
  GlobalVariable *AFLPrevLoc = new GlobalVariable(
      M, Int32Ty, false, GlobalValue::ExternalLinkage, 0, "__afl_prev_loc",
      0, GlobalVariable::GeneralDynamicTLSModel, 0, false);


  /*   global vector for storing  multi_in_edge            */
  typedef u16 PREV_LOC_T;
  
  unsigned PrevLocSize;
  //  fxm: the vector size could be set 1~n, max n = 8 is appriciated, n = 3 may be better ;
  char *mps_size_str = getenv("AFL_LLVM_MPS_SIZE");
  if (!mps_size_str) {
    PrevLocSize= 3;                                //  default 3            
  }
  else{
    if (sscanf(mps_size_str, "%u", &mps_size) != 1 || mps_size < 2 ||
        mps_size > MPS_SIZE_MAX)
      FATAL(
          "Bad value of AFL_LLVM_MLPS_SIZE (must be between 2 and MPS_SIZE_MAX "
          "(%u))",
          MPS_SIZE_MAX);

    if (mps_size == 1) mps_size = 0;
    if (mps_size)
      PrevLocSize = mps_size ;
    else
      PrevLocSize = 1;
  }
  outs()<<"[********************** THE MPS SIZE IS : "<<PrevLocSize<<"**************************]\n";
  
  

  IntegerType *IntLocTy =
      IntegerType::getIntNTy(C, sizeof(PREV_LOC_T) * CHAR_BIT);

  VectorType *PrevLocTy = NULL;
  PrevLocTy = VectorType::get(IntLocTy, PrevLocSize);

  GlobalVariable *AFLMultiInEdge;
  AFLMultiInEdge = new GlobalVariable(
        M, PrevLocTy, /* isConstant */ false, GlobalValue::ExternalLinkage,
        /* Initializer */ nullptr, "__afl_multi_in_edge",
        /* InsertBefore */ nullptr, GlobalVariable::GeneralDynamicTLSModel,
        /* AddressSpace */ 0, /* IsExternallyInitialized */ false);

  SmallVector<Constant *, 32> PrevLocShuffle = {UndefValue::get(Int32Ty)};

  for (unsigned I = 0; I < PrevLocSize-1; ++I)
    PrevLocShuffle.push_back(ConstantInt::get(Int32Ty, I));


  Constant *PrevLocShuffleMask = ConstantVector::get(PrevLocShuffle);
  /*   global vector for storing  multi_in_edge          */


  /* Instrument all the things! */

  int inst_blocks = 0;
  int cur_is_multi_bb = 2;
  int hash4_blocks = 0;
  int hash3_blocks = 0;

  

  for (auto &F : M){
    std::string funcName = F.getName().str();

    llvm::LoopInfo *LI = nullptr;

    if (!F.isDeclaration()) {
      LI = &getAnalysis<LoopInfoWrapperPass>(F).getLoopInfo();
    }

    /* Black list of function names */
    if (isBlacklisted(&F)) {
      continue;
    }

    if (!isInInstrumentList(&F, MNAME)) { continue; }

    std::vector<std::pair<BasicBlock::iterator, int>> ips_and_bb_flag ;

    for(auto &bb : F){
      int bbflag = 2;
      std::vector<BasicBlock *> preds;
      preds.clear();
      for (auto I = pred_begin(&bb), E = pred_end(&bb); I != E; ++I){preds.push_back(*I);}

      if (deter_multi_input(bb)){
        if (LI){
          llvm::Loop *L = LI->getLoopFor(&bb);
          if (!L || L->getHeader() != &bb) {
            bbflag = 3;
          }
        }
        else{
          bbflag = 3;
        }
      }
      if (bbflag ==3){
        hash3_blocks++;
        ips_and_bb_flag.push_back(std::make_pair(bb.getFirstInsertionPt(), bbflag));
        continue;
      }


      for (size_t i =0; i< preds.size(); ++i){
        if (deter_multi_output(*(preds[i]))) {
          if (LI){
            llvm::Loop *L = LI->getLoopFor(preds[i]);
            if (!L || L->getHeader() != preds[i]) {
              bbflag = 4;
              hash4_blocks++;
            }
          }
          else{
            bbflag = 4;
            hash4_blocks++;
          }
        }
      }

      ips_and_bb_flag.push_back(std::make_pair(bb.getFirstInsertionPt(), bbflag));
    }

  
    for (auto &pair : ips_and_bb_flag) {
    
      cur_is_multi_bb = pair.second;
      
      BasicBlock::iterator IP = pair.first;  
      IRBuilder<> IRB(&(*IP));

      if (AFL_R(100) >= inst_ratio) continue;

      /* Make up cur_loc */

      unsigned int cur_loc = AFL_R(MAP_SIZE);

      ConstantInt *CurLoc = ConstantInt::get(Int32Ty, cur_loc);

      /* Load prev_loc */

      LoadInst *PrevLoc = IRB.CreateLoad(AFLPrevLoc);
      PrevLoc->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
      Value *PrevLocCasted = IRB.CreateZExt(PrevLoc, IRB.getInt32Ty());

      /* Load SHM pointer */

      LoadInst *MapPtr = IRB.CreateLoad(AFLMapPtr);
      MapPtr->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

      Value *Edge_1 = IRB.CreateXor(PrevLocCasted, CurLoc);

      Value *MapPtrIdx =
          IRB.CreateGEP(MapPtr, Edge_1);

      /* Update bitmap */

      if (cur_is_multi_bb==3){

        /* Load multi_in_edge */

        LoadInst *MultiInEdge = IRB.CreateLoad(AFLMultiInEdge);
        MultiInEdge->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

        Value *ShuffledPrevLoc = IRB.CreateShuffleVector(
            MultiInEdge, UndefValue::get(PrevLocTy), PrevLocShuffleMask);
        Value *UpdatedPrevLoc = IRB.CreateInsertElement(
            ShuffledPrevLoc, Edge_1, (uint64_t)0);

        StoreInst *Store = IRB.CreateStore(UpdatedPrevLoc, AFLMultiInEdge);
        Store->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
      }

      if (cur_is_multi_bb == 4){
        /* Hash  mutli_in_edge and multi_out_edge*/

        LoadInst *MultiInEdge = IRB.CreateLoad(AFLMultiInEdge);
        MultiInEdge->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

        Value *PrevLocTrans;
        PrevLocTrans =
              IRB.CreateZExt(IRB.CreateXorReduce(MultiInEdge), IRB.getInt32Ty());
        
        Value *Map2idx = IRB.CreateXor(PrevLocTrans, Edge_1);

        ConstantInt *Offset = ConstantInt::get(Int32Ty, MAP_SIZE);                     //    use 64k~128k idx of the 128k bigger map as the second bitmap
        Value *NewMap2idx = IRB.CreateAdd(Map2idx, Offset);                            // 
 
        Value *MapPtrIdx_2 =
          IRB.CreateGEP(MapPtr, NewMap2idx);

        LoadInst *Counter_2 = IRB.CreateLoad(MapPtrIdx_2);
        Counter_2->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
        Value *Incr_2 = IRB.CreateAdd(Counter_2, ConstantInt::get(Int8Ty, 1));
        IRB.CreateStore(Incr_2, MapPtrIdx_2)
          ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

      }


      LoadInst *Counter = IRB.CreateLoad(MapPtrIdx);
      Counter->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
      Value *Incr = IRB.CreateAdd(Counter, ConstantInt::get(Int8Ty, 1));
      IRB.CreateStore(Incr, MapPtrIdx)
          ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

      /* Set prev_loc to cur_loc >> 1 */

      StoreInst *Store =
          IRB.CreateStore(ConstantInt::get(Int32Ty, cur_loc >> 1), AFLPrevLoc);
      Store->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

      inst_blocks++;

    }

  }
  
  // outs()<<"[************************************************]the blocks num is:"<<inst_blocks<<"|| the 4hash and 3hash mps bb num is:"
  // <<hash4_blocks<< "||"<<hash3_blocks<<"\n";
  

  /* Say something nice. */

  if (!be_quiet) {

    if (!inst_blocks) WARNF("No instrumentation targets found.");
    else OKF("Instrumented %u locations (%s mode, ratio %u%%).",
             inst_blocks, getenv("AFL_HARDEN") ? "hardened" :
             ((getenv("AFL_USE_ASAN") || getenv("AFL_USE_MSAN")) ?
              "ASAN/MSAN" : "non-hardened"), inst_ratio);

  }

  return true;

}


static void registerAFLPass(const PassManagerBuilder &,
                            legacy::PassManagerBase &PM) {

  PM.add(new AFLCoverage());

}


static RegisterStandardPasses RegisterAFLPass(
    PassManagerBuilder::EP_ModuleOptimizerEarly, registerAFLPass);

static RegisterStandardPasses RegisterAFLPass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerAFLPass);
