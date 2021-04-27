//===--- CGCheriCast.h - Checking pointer casts -----------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This contains code for generating allocation descriptions used when checking
// casts of pointer types
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_CGCHERICAST_H
#define LLVM_CGCHERICAST_H

#include "clang/AST/Type.h"

#include <llvm/IR/GlobalVariable.h>
#include <string>

namespace clang {
  class QualType;
  class CallExpr;
  namespace CodeGen {
    class CodeGenModule;
    class CodeGenFunction;
    class RValue;
    class CGCallee;
  }
}
typedef std::pair<llvm::Value*, llvm::Value*> PointerOTypePair;

llvm::GlobalVariable *
GetOrCreateGlobalAllocDescriptor(clang::CodeGen::CodeGenModule &CGM, clang::QualType Type);

unsigned cheriGetTypeCode(const clang::Type *Type);
llvm::Constant *EmitOtype(clang::CodeGen::CodeGenModule &CGM, clang::QualType Type);
llvm::Value *SealCapability(clang::CodeGen::CodeGenFunction &CGF, llvm::Value *Cap,
                            const clang::PointerType *OutType, llvm::Value *Type);
llvm::Value *SealCapability(clang::CodeGen::CodeGenFunction &CGF, llvm::Value *Cap, const clang::PointerType* Type);
llvm::Value *UnsealCapability(clang::CodeGen::CodeGenFunction &CGF, llvm::Value *Cap, const clang::PointerType* Type);
PointerOTypePair UnsealDynamicCapability(clang::CodeGen::CodeGenFunction &CGF, llvm::Value *Cap, const clang::PointerType* Type);
void EmitStaticUnsealedTypeCheck(clang::CodeGen::CodeGenFunction &CGF, llvm::Value *InCap, const clang::PointerType* Type);

/// Returns nullptr for OType if Type is not DynamicSealed.
PointerOTypePair EmitAppropriateUnseal(clang::CodeGen::CodeGenFunction &CGF, llvm::Value *InCap, const clang::PointerType *Type);
llvm::Value *EmitAppropriateSeal(clang::CodeGen::CodeGenFunction &CGF, PointerOTypePair PtrOTypePair, const clang::PointerType *Type);
clang::CodeGen::RValue EmitTaggedMalloc(clang::CodeGen::CodeGenFunction &CGF, const clang::Expr *SizeExpr, clang::QualType TypeArg, clang::PointerSealingKind PSK);
clang::CodeGen::RValue EmitTaggedMallocCall(clang::CodeGen::CodeGenFunction &CGF, clang::QualType CalleeType, const clang::CodeGen::CGCallee &OrigCallee, const clang::CallExpr *E);
#endif // LLVM_CGCHERICAST_H
