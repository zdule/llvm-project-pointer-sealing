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

#include <string>

namespace clang {
  class QualType;
  namespace CodeGen {
    class CodeGenModule;
  }
}

std::string GetOrCreateGlobalAllocDescriptor(clang::CodeGen::CodeGenModule &CGM, clang::QualType Type);

#endif // LLVM_CGCHERICAST_H
