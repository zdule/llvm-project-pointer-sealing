//===--- CGCheriCast.cpp - Checking pointer casts ---------------*- C++ -*-===//
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

#include "CGCheriCast.h"

#include "CodeGenModule.h"
#include "ConstantEmitter.h"
#include "clang/AST/Type.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/Casting.h"
#include <string>
#include <sstream>
#include <iterator>
#include <iostream>

using namespace clang;
using namespace llvm;
using namespace clang::CodeGen;

struct InternalEntry
{
  bool External;
  unsigned Multiplicity;
  unsigned Type;
};

struct ExternalEntry
{
  bool Final;
  unsigned Offset;
  unsigned Type;
};

const unsigned BytesInBucket = 4;

// Type wide enough to contain targets size_t
// uint64_t used elsewhere (In ASTRecordLayout to represent offsets)
typedef uint64_t target_size_t;
typedef std::pair<target_size_t, const clang::Type*> OffsetTypePair;
typedef std::vector<OffsetTypePair> TypeOffsets;
struct AllocationDescription
{
  target_size_t repeatOffset;
  target_size_t repeatSize;
  TypeOffsets offsets;

  std::vector<InternalEntry> internal;
  std::vector<ExternalEntry> external;
};

static void appendContainedTypeOffsets(CodeGenModule &CGM, const clang::Type *Type,
                                       target_size_t startOffset, AllocationDescription &desc) {
  if (!Type)
    llvm_unreachable("Type is null");
  desc.offsets.push_back({startOffset,Type});
  ASTContext &Context = CGM.getContext();
  if (Type->isScalarType()) {
    // pass
  }
  else if (Type->isRecordType()) {
    RecordDecl *Rec = cast<RecordType>(Type)->getDecl();
    Rec = Rec->getDefinition();
    if (Rec == nullptr)
        llvm_unreachable("Found undefined record type");
    const ASTRecordLayout &Layout = Context.getASTRecordLayout(Rec);
    for (FieldDecl *f : Rec->fields())
      appendContainedTypeOffsets(CGM, f->getType().getTypePtrOrNull(),
                                 Layout.getFieldOffset(f->getFieldIndex())/CGM.getTarget().getCharWidth(), desc);
  }
  else if (Type->isArrayType())
  {
    const clang::ArrayType *ArrayTy = Type->getAsArrayTypeUnsafe();
    const clang::Type *ElemTy = ArrayTy->getElementType().getTypePtrOrNull();
    const TypeInfo ElemTyInfo = Context.getTypeInfo(ElemTy);
    if (Type->isConstantArrayType()) {
      // This should work because ArrayType is already canonized
      target_size_t Size = cast<ConstantArrayType>(ArrayTy)->getSize().getZExtValue();
      for (target_size_t i = 0; i < Size; i++)
        appendContainedTypeOffsets(CGM, ElemTy, startOffset+i*ElemTyInfo.Width/CGM.getTarget().getCharWidth(), desc);
    }
    else if (Type->isIncompleteArrayType()) {
      // A repeating element starts here;
      assert(desc.repeatSize == 0 && "Found second variable array in the allocation");
      desc.repeatOffset = startOffset;
      desc.repeatSize = ElemTyInfo.Width/CGM.getTarget().getCharWidth();
      appendContainedTypeOffsets(CGM, ElemTy, startOffset, desc);
    }
    else
      llvm_unreachable("Unsupported type (scalars, constant/incomplete arrays, and records supported");
  }
  else
    llvm_unreachable("Unsupported type (scalars, constant/incomplete arrays, and records supported");
}

static unsigned getTypeCode(const clang::Type *Type) {
  return ((uintptr_t)Type)>>2 & ((1<<20) -1);
}

// assumes that offsets are de-duplicated, with offsets module BytesInBucket
// A Bucket can be described by an InternalEntry if:
//   - it's empty
//   - it contains the start of a single object
//   - it contains up to 4 objects of the same type which are packed to the start
//     of the bucket
static Optional<InternalEntry> tryFitInInternalEntry(CodeGenModule &CGM, const std::vector<OffsetTypePair> &offsets) {
  if (offsets.empty())
    return InternalEntry {0, 0, 0};
  if (offsets.size() > BytesInBucket)
    return {};
  const clang::Type *Type = offsets.front().second;
  bool SameType = std::all_of(offsets.begin(), offsets.end(),
                              [Type](const OffsetTypePair &p) {
                                return p.second == Type;
                              });
  if (!SameType)
    return {};

  target_size_t ExpectedOffset = 0;
  target_size_t TypeSize = CGM.getContext().getTypeInfo(Type).Width/CGM.getTarget().getCharWidth();
  for (auto p : offsets) {
    // Objects are not typed, cannot fit into a single entry
    if (p.first != ExpectedOffset)
      return {};

    ExpectedOffset += TypeSize;
  }

  // Objects are packed.
  return InternalEntry {0, (unsigned) offsets.size(), getTypeCode(Type)};
}

static InternalEntry getEntryForBucket(CodeGenModule &CGM, std::vector<OffsetTypePair> &offsets, std::vector<ExternalEntry> &external)
{
  if (offsets.empty())
    return {false, 0, 0};

  // Dedup
  auto last = std::unique(offsets.begin(), offsets.end());
  offsets.erase(last, offsets.end());

  // Modulo offsets
  for (auto &p : offsets)
    p.first %= BytesInBucket;

  // Try internal entries
  if (Optional<InternalEntry> e = tryFitInInternalEntry(CGM, offsets))
    return e.getValue();

  InternalEntry e {1, 0, (unsigned) external.size()};
  // generate External entries
  for (const auto &p : offsets)
    external.push_back(ExternalEntry{&p == &offsets.back(), (unsigned)p.first, getTypeCode(p.second)});
  return e;
}

static void compressOffsetsToEntries(CodeGenModule &CGM, target_size_t Size, AllocationDescription &desc)
{
  std::vector<InternalEntry> &internal = desc.internal;
  std::vector<ExternalEntry> &external = desc.external;

  target_size_t NBuckets = (Size+BytesInBucket-1)/BytesInBucket;
  internal.resize(NBuckets);

  std::vector<std::vector<OffsetTypePair>> Buckets(NBuckets);
  for (OffsetTypePair p : desc.offsets)
    Buckets[p.first/BytesInBucket].push_back(p);

  for (target_size_t i = 0; i < internal.size(); i++)
    internal[i] = getEntryForBucket(CGM, Buckets[i], external);
}

static APValue intValue(unsigned bits, unsigned val)
{
  return APValue(APSInt(APInt(bits, val)));
}

static APValue convertAllocDescToAPValue(CodeGenModule &CGM, AllocationDescription &desc)
{
  RecordDecl *AllocDescDecl = CGM.getContext().getCHERICastAllocDescDecl();
  auto FieldIt = AllocDescDecl->field_begin();
  std::advance(FieldIt,3);
  const RecordDecl *UnionDecl = FieldIt->getType()->castAsArrayTypeUnsafe()->
      getElementType()->castAs<RecordType>()->getDecl();
  const FieldDecl *InternalEntryDecl = *UnionDecl->field_begin();
  const FieldDecl *ExternalEntryDecl = *(++(UnionDecl->field_begin()));

  APValue Value(APValue::UninitStruct(), 0, 4);
  // In bits
  uint64_t TargetSizeTWidth = CGM.getContext().getTypeSize(CGM.getContext().getSizeType());

  Value.getStructField(0) = APValue(APSInt(APInt(TargetSizeTWidth, desc.repeatOffset)));
  Value.getStructField(1) = APValue(APSInt(APInt(TargetSizeTWidth, desc.repeatSize)));
  Value.getStructField(2) = APValue(APSInt(APInt(TargetSizeTWidth,desc.internal.size())));

  target_size_t NFields = desc.internal.size() + desc.external.size();
  APValue &FieldsValue = Value.getStructField(3);
  FieldsValue = APValue(APValue::UninitArray(), NFields, NFields);

  for (int i = 0; i < desc.internal.size(); i++)
  {
    APValue &ElValue = FieldsValue.getArrayInitializedElt(i);
    ElValue = APValue(InternalEntryDecl);
    APValue &InternalStruct = ElValue.getUnionValue();
    InternalStruct = APValue(APValue::UninitStruct{}, 0, 3);
    InternalStruct.getStructField(0) = intValue(1, desc.internal[i].External);
    InternalStruct.getStructField(1) = intValue(3, desc.internal[i].Multiplicity);
    InternalStruct.getStructField(2) = intValue(20, desc.internal[i].Type);
  }
  for (int i = 0; i < desc.external.size(); i++)
  {
    APValue &ElValue = FieldsValue.getArrayInitializedElt(desc.internal.size()+i);
    ElValue = APValue(ExternalEntryDecl);
    APValue &InternalStruct = ElValue.getUnionValue();
    InternalStruct = APValue(APValue::UninitStruct{}, 0, 3);
    InternalStruct.getStructField(0) = intValue(1, desc.external[i].Final);
    InternalStruct.getStructField(1) = intValue(3, desc.external[i].Offset);
    InternalStruct.getStructField(2) = intValue(20, desc.external[i].Type);
  }

  Value.printPretty(llvm::outs(), CGM.getContext(), CGM.getContext().getCHERICastAllocDescType());
  return Value;
}

static APValue createAllocDescStruct(CodeGenModule &CGM, QualType Type)
{
  // Initialize all fields to 0
  AllocationDescription desc = {};
  target_size_t Size = CGM.getContext().getTypeInfo(Type).Width/CGM.getTarget().getCharWidth();
  desc.repeatOffset = Size;
  appendContainedTypeOffsets(CGM, Type.getTypePtrOrNull(), 0, desc);

  std::stable_sort(desc.offsets.begin(), desc.offsets.end());
  compressOffsetsToEntries(CGM, Size, desc);
  return convertAllocDescToAPValue(CGM, desc);
}

std::string GetOrCreateGlobalAllocDescriptor(CodeGenModule &CGM, QualType Type)
{
  auto &M = CGM.getModule();
  std::ostringstream Name("__cheri_allocation_tag_");
  Name << Type.getTypePtr();
  auto *GlobalDesc = M.getNamedGlobal(Name.str());
  if (GlobalDesc)
    return Name.str();
  QualType DescType = CGM.getContext().getCHERICastAllocDescType();
  llvm::Type *GlobalType = CGM.getTypes().ConvertTypeForMem(DescType, false);
  ConstantEmitter CE(CGM);
  APValue Value = createAllocDescStruct(CGM, Type);
  Constant *DescConst = CE.tryEmitAbstract(Value, DescType);
  new llvm::GlobalVariable(
      M, GlobalType,
      true, llvm::GlobalValue::ExternalLinkage,  DescConst,
      "__cheri_sealing_capability", nullptr,
      llvm::GlobalValue::NotThreadLocal, 200);
  return Name.str();
}