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
#include "clang/CodeGen/ConstantInitBuilder.h"
#include "clang/Basic/DiagnosticSema.h"
#include "ConstantEmitter.h"
#include "clang/AST/Type.h"
#include "clang/AST/StmtVisitor.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/Casting.h"
#include <string>
#include <sstream>
#include <iostream>

using namespace clang;
using namespace clang::CodeGen;

struct InternalEntry
{
  bool External;
  unsigned Multiplicity;
  //unsigned Type;
  llvm::Constant *OType;
  llvm::Constant *getValue(llvm::LLVMContext &LLVMContext) const
  {
    llvm::Constant *UpperBits
        = llvm::ConstantInt::get(LLVMContext, llvm::APInt(32, (External<<31) | (Multiplicity << 28)));
    return llvm::ConstantExpr::
        getAdd(UpperBits, llvm::ConstantExpr::getTrunc(OType, llvm::IntegerType::get(LLVMContext, 32)));
    // return (External << 31) | (Multiplicity << 28) | Type;
  }
};

struct ExternalEntry
{
  bool Final;
  unsigned Offset;
  //unsigned Type;
  llvm::Constant *OType;
  llvm::Constant *getValue(llvm::LLVMContext &LLVMContext) const
  {
    llvm::Constant *UpperBits
        = llvm::ConstantInt::get(LLVMContext, llvm::APInt(32, (Final<<31) | (Offset << 28)));
    return llvm::ConstantExpr::
        getAdd(UpperBits, llvm::ConstantExpr::getTrunc(OType, llvm::IntegerType::get(LLVMContext, 3)));
  }
};

const unsigned BytesInBucket = 4;

// Type wide enough to contain targets size_t
// uint64_t used elsewhere (In ASTRecordLayout to represent offsets)
typedef uint64_t target_size_t;
typedef std::pair<CharUnits, QualType> OffsetTypePair;
typedef std::vector<OffsetTypePair> TypeOffsets;
struct AllocationDescription
{
  CharUnits repeatOffset;
  CharUnits repeatSize;
  TypeOffsets offsets;

  std::vector<InternalEntry> internal;
  std::vector<ExternalEntry> external;
};

static void appendContainedTypeOffsets(CodeGenModule &CGM, QualType Type,
                                       CharUnits startOffset, AllocationDescription &desc) {
  if (Type.isNull())
    llvm_unreachable("Type is null");
  desc.offsets.push_back({startOffset,Type});
  ASTContext &Context = CGM.getContext();
  if (Type->isScalarType()) {
    // pass
  }
  else if (Type->isRecordType()) {
    RecordDecl *Rec = Type->getAsRecordDecl();
    Rec = Rec->getDefinition();
    if (Rec == nullptr)
        llvm_unreachable("Found undefined record type");
    const ASTRecordLayout &Layout = Context.getASTRecordLayout(Rec);
    for (FieldDecl *f : Rec->fields()) {
      if (f->isBitField())
        continue;
      CharUnits fieldOffset = CharUnits::fromQuantity(Layout.getFieldOffset(f->getFieldIndex()) /
                                                      CGM.getTarget().getCharWidth());
      appendContainedTypeOffsets(CGM, f->getType(),
                                 startOffset + fieldOffset, desc);
    }
  }
  else if (Type->isArrayType())
  {
    const clang::ArrayType *ArrayTy = Type->getAsArrayTypeUnsafe();
    QualType ElemTy = ArrayTy->getElementType();
    const CharUnits ElemSize = Context.getTypeSizeInChars(ElemTy);
    if (Type->isConstantArrayType()) {
      // This should work because ArrayType is already canonized
      target_size_t Size = cast<ConstantArrayType>(ArrayTy)->getSize().getZExtValue();
      for (target_size_t i = 0; i < Size; i++)
        appendContainedTypeOffsets(CGM, ElemTy, startOffset+i*ElemSize, desc);
    }
    else if (Type->isIncompleteArrayType()) {
      // A repeating element starts here;
      assert(desc.repeatSize.isZero() && "Found second variable array in the allocation");
      desc.repeatOffset = startOffset;
      desc.repeatSize = ElemSize;
      appendContainedTypeOffsets(CGM, ElemTy, startOffset, desc);
    }
    else
      llvm_unreachable("Unsupported type (scalars, constant/incomplete arrays, and records supported");
  }
  else
    llvm_unreachable("Unsupported type (scalars, constant/incomplete arrays, and records supported");
}

// assumes that offsets are de-duplicated, with offsets module BytesInBucket
// A Bucket can be described by an InternalEntry if:
//   - it's empty
//   - it contains the start of a single object
//   - it contains up to 4 objects of the same type which are packed to the start
//     of the bucket
static Optional<InternalEntry> tryFitInInternalEntry(CodeGenModule &CGM, const std::vector<OffsetTypePair> &offsets) {
  if (offsets.empty())
    return InternalEntry {0, 0, llvm::ConstantInt::get(CGM.SizeTy,0)};
  if (offsets.size() > BytesInBucket)
    return {};
  QualType Type = offsets.front().second;
  bool SameType = std::all_of(offsets.begin(), offsets.end(),
                              [Type](const OffsetTypePair &p) {
                                return p.second == Type;
                              });
  if (!SameType)
    return {};

  CharUnits ExpectedOffset = {};
  CharUnits TypeSize = CGM.getContext().getTypeSizeInChars(Type);
  for (auto p : offsets) {
    // Objects are not typed, cannot fit into a single entry
    if (p.first != ExpectedOffset)
      return {};

    ExpectedOffset += TypeSize;
  }

  // Objects are packed.
  return InternalEntry {0, (unsigned) offsets.size(), EmitOtype(CGM, Type)};
}

static InternalEntry getEntryForBucket(CodeGenModule &CGM, std::vector<OffsetTypePair> &offsets, std::vector<ExternalEntry> &external)
{
  if (offsets.empty())
    return {false, 0, llvm::ConstantInt::get(CGM.SizeTy, 0)};

  // Dedup
  auto last = std::unique(offsets.begin(), offsets.end());
  offsets.erase(last, offsets.end());

  // Modulo offsets
  for (auto &p : offsets)
    p.first = p.first % BytesInBucket;

  // Try internal entries
  if (Optional<InternalEntry> e = tryFitInInternalEntry(CGM, offsets))
    return e.getValue();

  InternalEntry e {1, 0, llvm::ConstantInt::get(CGM.Int32Ty, external.size())};
  // generate External entries
  for (const auto &p : offsets)
    external.push_back(ExternalEntry{&p == &offsets.back(), (unsigned)p.first.getQuantity(),
                                     EmitOtype(CGM, p.second)});
  return e;
}

static void compressOffsetsToEntries(CodeGenModule &CGM, CharUnits Size, AllocationDescription &desc)
{
  std::vector<InternalEntry> &internal = desc.internal;
  std::vector<ExternalEntry> &external = desc.external;

  long NBuckets = (Size.getQuantity()+BytesInBucket-1)/BytesInBucket;
  internal.resize((size_t)NBuckets);

  std::vector<std::vector<OffsetTypePair>> Buckets((size_t)NBuckets);
  for (OffsetTypePair p : desc.offsets)
    Buckets[p.first.getQuantity()/BytesInBucket].push_back(p);

  for (target_size_t i = 0; i < internal.size(); i++)
    internal[i] = getEntryForBucket(CGM, Buckets[i], external);
}

static APValue intValue(unsigned bits, uint64_t val)
{
  return APValue(llvm::APSInt(llvm::APInt(bits, val)));
}

/*
static APValue convertAllocDescToAPValue(CodeGenModule &CGM, AllocationDescription &desc)
{
  APValue Value(APValue::UninitStruct(), 0, 4);
  // In bits
  uint64_t TargetSizeTWidth = CGM.getContext().getTypeSize(CGM.getContext().getSizeType());
  uint64_t UnsignedIntSize = CGM.getTarget().getIntWidth();

  Value.getStructField(0) = intValue(TargetSizeTWidth, desc.repeatOffset.getQuantity());
  Value.getStructField(1) = intValue(TargetSizeTWidth, desc.repeatSize.getQuantity());
  Value.getStructField(2) = intValue(TargetSizeTWidth, desc.internal.size());

  unsigned int NFields = (unsigned int) (desc.internal.size() + desc.external.size());
  APValue &FieldsValue = Value.getStructField(3);
  FieldsValue = APValue(APValue::UninitArray(), NFields, NFields);

  for (int i = 0; i < desc.internal.size(); i++)
  {
    FieldsValue.getArrayInitializedElt(i) = intValue(32, desc.internal[i].getValue());
  }
  for (int i = 0; i < desc.external.size(); i++)
  {
    FieldsValue.getArrayInitializedElt(desc.internal.size()+i) =
        intValue(UnsignedIntSize, desc.external[i].getValue());
  }

  Value.printPretty(llvm::outs(), CGM.getContext(), CGM.getContext().getCHERICastAllocDescType());
  return Value;
}
*/

static AllocationDescription createAllocDescStruct(CodeGenModule &CGM, QualType Type)
{
  // Initialize all fields to 0
  AllocationDescription desc = {};
  CharUnits Size = CGM.getContext().getTypeSizeInChars(Type);
  desc.repeatOffset = Size;
  if (!Type->isStructureType() || !Type->getAsRecordDecl()->hasFlexibleArrayMember()) {
    desc.repeatOffset = CharUnits::Zero();
    desc.repeatSize = Size;
  }
  appendContainedTypeOffsets(CGM, Type, CharUnits(), desc);

  std::stable_sort(desc.offsets.begin(), desc.offsets.end());
  compressOffsetsToEntries(CGM, Size, desc);
  return desc;
}

llvm::GlobalVariable *EmitAllocDescGlobalVar(CodeGenModule &CGM, const AllocationDescription &desc, std::string Name) {
  ConstantInitBuilder builder(CGM);
  auto toplevel = builder.beginStruct();
  toplevel.addInt(CGM.SizeTy, desc.repeatOffset.getQuantity());
  toplevel.addInt(CGM.SizeTy, desc.repeatSize.getQuantity());
  toplevel.addInt(CGM.SizeTy, desc.internal.size());

  if (!desc.internal.empty()) {
  auto InternalArray = toplevel.beginArray();
    for (int i = 0; i < desc.internal.size(); i++)
    {
      InternalArray.add(desc.internal[i].getValue(CGM.getModule().getContext()));
    }
    InternalArray.finishAndAddTo(toplevel);
  }

  if (!desc.external.empty()) {
    auto ExternalArray = toplevel.beginArray();
    for (int i = 0; i < desc.external.size(); i++) {
      ExternalArray.add(
          desc.external[i].getValue(CGM.getModule().getContext()));
    }
    ExternalArray.finishAndAddTo(toplevel);
  }
  ASTContext &Context = CGM.getContext();
  return toplevel.finishAndCreateGlobal(Name, Context.getAlignOfGlobalVarInChars(Context.getCHERICastAllocDescType()),
                                        true, llvm::GlobalVariable::WeakAnyLinkage, 200);
}

void BuildOTypeString(ASTContext &Context, QualType Type, std::ostream &stream) {
  if (Type.isConstQualified()) {
    stream << "C";
  }
  if (Type->isBuiltinType()) {
    const char *str = "invalid";
    switch(Type->castAs<BuiltinType>()->getKind()) {
    case BuiltinType::Kind::Void:
      str = "v";
      break;
    case BuiltinType::Kind::Bool:
      str = "b";
      break;
    case BuiltinType::Kind::Char_U:
      str = "c";
      break;
    case BuiltinType::Kind::Char_S:
      str = "c";
      break;
    case BuiltinType::Kind::SChar:
      str = "sc";
      break;
    case BuiltinType::Kind::UChar:
      str = "uc";
      break;
    case BuiltinType::Kind::Short:
      str = "h";
      break;
    case BuiltinType::Kind::Int:
      str = "i";
      break;
    case BuiltinType::Kind::Long:
      str = "l";
      break;
    case BuiltinType::Kind::LongLong:
      str = "L";
      break;
    case BuiltinType::Kind::Int128:
      str = "8";
      break;
    case BuiltinType::Kind::UShort:
      str = "uh";
      break;
    case BuiltinType::Kind::UInt:
      str = "ui";
      break;
    case BuiltinType::Kind::ULong:
      str = "ul";
      break;
    case BuiltinType::Kind::ULongLong:
      str = "uL";
      break;
    case BuiltinType::Kind::UInt128:
      str = "u8";
      break;
    case BuiltinType::Kind::Float:
      str = "f";
      break;
    case BuiltinType::Kind::Double:
      str = "d";
      break;
    case BuiltinType::Kind::LongDouble:
      str = "D";
      break;
    default:
      Type.dump();
      llvm_unreachable("Unsupported builtin type");
    }
    stream << str;
  }
  else if (Type->isPointerType()) {
    stream << "*";
    BuildOTypeString(Context, Type->getPointeeType(), stream);
  }
  else if (const AtomicType *AT = Type->getAs<AtomicType>()) {
    stream << "A";
    BuildOTypeString(Context, AT->getValueType(), stream);
  }
  else if (Type->isConstantArrayType())
  {
    const ConstantArrayType *AT = static_cast<const ConstantArrayType*>(
        Type->getAsArrayTypeUnsafe());
    stream << "[" << AT->getSize().getZExtValue() << "]";
    BuildOTypeString(Context, AT->getElementType(), stream);
  }
  else if (const RecordType *RT = Type->getAsStructureType()) {
    RecordDecl *Rec = RT->getAsRecordDecl();
    std::string Name = Rec->getNameAsString();
    stream << "{" << Name;
    Rec = Rec->getDefinition();
    if (Rec != nullptr) {
      stream << ":";
      const ASTRecordLayout &Layout = Context.getASTRecordLayout(Rec);
      for (FieldDecl *f : Rec->fields()) {
        stream << f->getNameAsString();
        if (f->isBitField()) {
          stream << "%" << f->getBitWidthValue(Context);
        }
        stream << ":";
        BuildOTypeString(Context, f->getType(), stream);
      }
    }
    stream << "}";
  }
  else if (const RecordType *RT = Type->getAsUnionType()) {
    RecordDecl *Rec = RT->getAsRecordDecl();
    std::string Name = Rec->getNameAsString();
    stream << "|" << Name;
    Rec = Rec->getDefinition();
    if (Rec != nullptr) {
      stream << ":";
      const ASTRecordLayout &Layout = Context.getASTRecordLayout(Rec);
      std::vector<std::pair<std::string, const FieldDecl*>> order;
      for (FieldDecl *f : Rec->fields()) {
        std::string FieldName = f->getNameAsString();
        if (FieldName.empty())
        {
          std::stringstream ss;
          BuildOTypeString(Context, f->getType(), ss);
          FieldName = ss.str();
        }
        order.push_back({FieldName, f});
      }
      sort(order.begin(), order.end());
      for (auto &p : order) {
        const FieldDecl *f = p.second;
        stream << f->getNameAsString();
        if (f->isBitField()) {
          stream << "%" << f->getBitWidthValue(Context);
        }
        stream << ":";
        BuildOTypeString(Context, f->getType(), stream);
      }
    }
    stream << "|";
  }
  else if (const FunctionProtoType *FTy = Type->getAs<FunctionProtoType>()) {
    stream << "(";
    BuildOTypeString(Context, FTy->getReturnType(), stream);
    for (QualType ArgTy : FTy->getParamTypes())
      BuildOTypeString(Context, ArgTy, stream);
    stream << ")";
  }
  else {
    Type.dump();
    llvm_unreachable("Unsupported Type");
  }
}

static std::string GetOTypeStringStart(ASTContext &Context, QualType Type)
{
  std::ostringstream Name;
  Name << "__cheri_otypeb_";
  BuildOTypeString(Context, Type, Name);
  return Name.str();
}
static std::string GetOTypeStringEnd(ASTContext &Context, QualType Type)
{
  std::ostringstream Name;
  Name << "__cheri_otypee_";
  BuildOTypeString(Context, Type, Name);
  return Name.str();
}
static std::string GetAllocDescString(ASTContext &Context, QualType Type)
{
  std::ostringstream Name;
  Name << "__cheri_alloc_desc_";
  BuildOTypeString(Context, Type, Name);
  return Name.str();
}

llvm::GlobalVariable *GetOrCreateGlobalAllocDescriptor(CodeGenModule &CGM, QualType Type)
{
  auto &M = CGM.getModule();
  std::string Name = GetAllocDescString(CGM.getContext(), Type);
  auto *GlobalDesc = M.getNamedGlobal(Name);
  if (GlobalDesc)
    return GlobalDesc;
  return EmitAllocDescGlobalVar(CGM, createAllocDescStruct(CGM, Type), Name);
}

const char *otype_section = "__cheri_otype_var_table";

llvm::Constant *EmitOTypeTableStart(CodeGenModule &CGM) {
  llvm::Module &M = CGM.getModule();
  const char *table_start_str = "__cheri_otype_table_start";
  llvm::GlobalVariable *OTypesStart = M.getNamedGlobal(table_start_str);
  if (!OTypesStart) {
    OTypesStart = new llvm::GlobalVariable(M, CGM.Int8Ty,
                                           false, llvm::GlobalValue::ExternalLinkage,
                                           nullptr, table_start_str,
                                           nullptr, llvm::GlobalValue::NotThreadLocal,
                                           200);
    OTypesStart->setSection(otype_section);
  }
  return OTypesStart;
}

/// Note, if calling for pointer T*, you most likely want
/// type to be T.
llvm::Constant *EmitOTypeStart(CodeGenModule &CGM, QualType Type)
{
  llvm::Module &M = CGM.getModule();
  std::string OTypeStartString = GetOTypeStringStart(CGM.getContext(), Type);

  llvm::Constant *TableStart = EmitOTypeTableStart(CGM);

  llvm::GlobalVariable *OTypeStartGlobal = M.getNamedGlobal(OTypeStartString);
  if (!OTypeStartGlobal) {
    OTypeStartGlobal = new llvm::GlobalVariable(M, CGM.Int8Ty,
                                             false, llvm::GlobalValue::ExternalLinkage,
                                             nullptr, OTypeStartString,
                                             nullptr, llvm::GlobalValue::NotThreadLocal,
                                             200);
    OTypeStartGlobal->setSection(otype_section);
  }
  llvm::Constant *OTypeOffset = llvm::ConstantExpr::getSub(
      llvm::ConstantExpr::getPtrToInt(OTypeStartGlobal, CGM.SizeTy),
      llvm::ConstantExpr::getPtrToInt(TableStart, CGM.SizeTy));
  return OTypeOffset;
}

/// Note, if calling for pointer T*, you most likely want
/// type to be T.
llvm::Constant *EmitOTypeEnd(CodeGenModule &CGM, QualType Type) {
  llvm::Module &M = CGM.getModule();
  std::string OTypeEndString = GetOTypeStringEnd(CGM.getContext(), Type);

  llvm::Constant *TableStart = EmitOTypeTableStart(CGM);
  llvm::GlobalVariable *OTypeEndGlobal = M.getNamedGlobal(OTypeEndString);
  if (!OTypeEndGlobal) {
    OTypeEndGlobal = new llvm::GlobalVariable(
        M, CGM.Int8Ty, false, llvm::GlobalValue::ExternalLinkage, nullptr,
        OTypeEndString, nullptr, llvm::GlobalValue::NotThreadLocal, 200);
    OTypeEndGlobal->setSection(otype_section);
  }
  llvm::Constant *OTypeEndOffset = llvm::ConstantExpr::getSub(
      llvm::ConstantExpr::getPtrToInt(OTypeEndGlobal, CGM.SizeTy),
      llvm::ConstantExpr::getPtrToInt(TableStart, CGM.SizeTy));
  return OTypeEndOffset;
}

/// Note, if calling for pointer T*, you most likely want
/// type to be T.
llvm::Constant *EmitOtype(clang::CodeGen::CodeGenModule &CGM, clang::QualType Type) {
  return EmitOTypeStart(CGM, Type);
}

bool IsUncheckedCastType(clang::QualType Type) {
  return Type->isAnyCharacterType() || Type->isVoidType();
}

llvm::Value *SealCapability(CodeGenFunction &CGF, llvm::Value *Cap,
                          const clang::PointerType *OutType, llvm::Value* OType) {
  llvm::Value *SealCap = CGF.GetOrCreateSealingCap();

  Cap = CGF.Builder.CreateBitCast(Cap, CGF.VoidCheriCapTy);
  SealCap = CGF.Builder.CreateIntrinsic(llvm::Intrinsic::cheri_cap_offset_set,
                                        {CGF.SizeTy},
                                        {SealCap, OType});
  Cap = CGF.Builder.CreateIntrinsic(llvm::Intrinsic::cheri_cap_seal, {},
                                    {Cap, SealCap});
  return CGF.Builder.CreateBitCast(Cap, CGF.ConvertType(QualType(OutType, 0)));
}

llvm::Value *SealCapability(CodeGenFunction &CGF, llvm::Value *Cap, const PointerType* Type) {
  llvm::Constant *OType = EmitOtype(CGF.CGM, Type->getPointeeType());
  return SealCapability(CGF, Cap, Type, OType);
}

llvm::Value *UnsealCapability(CodeGenFunction &CGF, llvm::Value *Cap, const PointerType* Type) {
  llvm::Value *SealCap = CGF.GetOrCreateSealingCap();
  llvm::Constant *OType = EmitOtype(CGF.CGM, Type->getPointeeType());

  Cap = CGF.Builder.CreateBitCast(Cap, CGF.VoidCheriCapTy);
  SealCap = CGF.Builder.CreateIntrinsic(llvm::Intrinsic::cheri_cap_offset_set,
                                        {CGF.SizeTy},
                                        {SealCap, OType});
  Cap = CGF.Builder.CreateIntrinsic(llvm::Intrinsic::cheri_cap_unseal, {},
                                    {Cap, SealCap});
  return CGF.Builder.CreateBitCast(Cap, CGF.ConvertType(QualType(Type, 0)));
}

void EmitBoundsCheck(CodeGenFunction &CGF, llvm::Value *Value, llvm::Value *Lower, llvm::Value *Upper) {
  llvm::FunctionCallee BoundsCheckFunction = CGF.CGM.getModule().
      getOrInsertFunction("__cheri_otype_bounds_check", CGF.VoidTy,
                          CGF.SizeTy, CGF.SizeTy, CGF.SizeTy);
  CGF.Builder.CreateCall(BoundsCheckFunction, {Value, Lower, Upper});
}

PointerOTypePair UnsealDynamicCapability(CodeGenFunction &CGF, llvm::Value *InCap, const PointerType* Type) {
  llvm::Value *SealCap = CGF.GetOrCreateSealingCap();
  llvm::Constant *OTypeStart = EmitOTypeStart(CGF.CGM, Type->getPointeeType());
  llvm::Constant *OTypeEnd = EmitOTypeEnd(CGF.CGM, Type->getPointeeType());

  InCap = CGF.Builder.CreateBitCast(InCap, CGF.VoidCheriCapTy);
  llvm::Value *OType = CGF.Builder.CreateIntrinsic(llvm::Intrinsic::cheri_cap_type_get,
                                               {CGF.SizeTy}, {InCap});

  if (!IsUncheckedCastType(Type->getPointeeType()))
    EmitBoundsCheck(CGF, OType, OTypeStart, OTypeEnd);
  SealCap = CGF.Builder.CreateIntrinsic(llvm::Intrinsic::cheri_cap_offset_set,
                                    {CGF.SizeTy},
                                    {SealCap, OType});
  InCap = CGF.Builder.CreateIntrinsic(llvm::Intrinsic::cheri_cap_unseal, {},
                                  {InCap, SealCap});
  InCap = CGF.Builder.CreateBitCast(InCap,CGF.ConvertType(QualType(Type, 0)));
  return PointerOTypePair(InCap, OType);
}

void EmitStaticUnsealedTypeCheck(CodeGenFunction &CGF, llvm::Value *InCap, const PointerType* Type) {
  QualType PointeeType = Type->getPointeeType();
  if (IsUncheckedCastType(PointeeType))
    return;
  llvm::Constant *OType = EmitOtype(CGF.CGM, PointeeType);
  llvm::Constant *Size =
      llvm::ConstantInt::get(CGF.SizeTy, CGF.getContext().
                                         getTypeSizeInChars(PointeeType).getQuantity());

  llvm::Value *VoidInCap = CGF.Builder.CreateBitCast(InCap, CGF.VoidCheriCapTy);
  llvm::FunctionCallee CheckFunction = CGF.CGM.getModule().
      getOrInsertFunction("__cheri_cast_check", CGF.VoidTy,
                          CGF.VoidCheriCapTy, CGF.SizeTy, CGF.SizeTy);
  CGF.Builder.CreateCall(CheckFunction, {VoidInCap, OType, Size});
}

PointerOTypePair EmitAppropriateUnseal(clang::CodeGen::CodeGenFunction &CGF, llvm::Value *InCap, const clang::PointerType *Type) {
  switch (Type->getSealingKind()) {
  case clang::PSK_Unsealed:
  case clang::PSK_StaticUnsealed:
    return PointerOTypePair(InCap, nullptr);
  case clang::PSK_DynamicSealed:
    return UnsealDynamicCapability(CGF, InCap, Type);
  case clang::PSK_StaticSealed:
    return PointerOTypePair(UnsealCapability(CGF, InCap, Type), nullptr);
  case clang::PSK_DynamicUnsealed:
    llvm_unreachable("DynamicUnsealed is not a scalar expr");
  default:
    llvm_unreachable("All cases should be covered");
  }
}

llvm::Value *EmitAppropriateSeal(clang::CodeGen::CodeGenFunction &CGF, PointerOTypePair PtrOTypePair, const clang::PointerType *Type) {
  assert((PtrOTypePair.second == nullptr) == (Type->getSealingKind() != PSK_DynamicSealed));
  switch (Type->getSealingKind()) {
  case clang::PSK_Unsealed:
  case clang::PSK_StaticUnsealed:
    return PtrOTypePair.first;
  case clang::PSK_DynamicSealed:
    return SealCapability(CGF, PtrOTypePair.first, Type, PtrOTypePair.second);
  case clang::PSK_StaticSealed:
    return SealCapability(CGF, PtrOTypePair.first, Type);
  case clang::PSK_DynamicUnsealed:
    llvm_unreachable("DynamicUnsealed is not a scalar expr");
  default:
    llvm_unreachable("All cases should be covered");
  }
}

RValue EmitTaggedMalloc(CodeGenFunction &CGF, const Expr *SizeExpr, QualType TypeArg, PointerSealingKind PSK) {
  llvm::Value *size = CGF.EmitScalarExpr(SizeExpr);
  llvm::GlobalVariable *AllocDescriptor = GetOrCreateGlobalAllocDescriptor(CGF.CGM, TypeArg);
  llvm::Value *CastDescriptor = CGF.Builder.CreateBitCast(AllocDescriptor, CGF.VoidPtrTy);

  llvm::FunctionCallee TaggedMallocFun =
      CGF.CGM.getModule().getOrInsertFunction("__cheri_tagged_malloc", CGF.VoidPtrTy, CGF.SizeTy, CGF.VoidPtrTy);
  llvm::Value *Ret = CGF.Builder.CreateCall(TaggedMallocFun,{size,CastDescriptor});
  switch (PSK) {
  case PSK_DynamicUnsealed:
    return RValue::getComplex(Ret, EmitOtype(CGF.CGM, TypeArg));
  case PSK_StaticUnsealed:
  case PSK_Unsealed:
    return RValue::get(Ret);
  default:
    llvm_unreachable("Only Unsealed types are supported");
  }
}

class SizeofTypeDeducer : public ConstStmtVisitor<SizeofTypeDeducer, QualType> {
public:

  QualType VisitBinMul(const BinaryOperator *E) {
    QualType A = Visit(E->getLHS());
    QualType B = Visit(E->getRHS());
    if (A.isNull()) return B;
    if (B.isNull()) return A;
    return QualType();
  }

  QualType VisitParenExpr(const ParenExpr *E) {
    return Visit(E->getSubExpr());
  }

  QualType VisitUnaryExprOrTypeTraitExpr(const UnaryExprOrTypeTraitExpr *E) {
    if (E->getKind() == UETT_SizeOf) {
      return E->getArgumentType();
    }
    return QualType();

  }
};

static QualType DeduceMallocSizeOfType(const Expr *E) {
 SizeofTypeDeducer Deducer;
 return Deducer.Visit(E);
}

RValue EmitTaggedMallocCall(CodeGenFunction &CGF, QualType CalleeType, const clang::CodeGen::CGCallee &OrigCallee, const clang::CallExpr *E) {
  QualType ArgT = DeduceMallocSizeOfType(E->getArg(0));
  const PointerType *RetType = E->getType()->castAs<PointerType>();
  if (ArgT.isNull()) {
    CGF.getContext().getDiagnostics().Report(E->getExprLoc(), diag::warn_unknown_malloc_type);
    llvm::Value *SizeVal = CGF.EmitScalarExpr(E->getArg(0));
    llvm::FunctionType *MallocTy = cast<llvm::FunctionType>(CGF.ConvertType(CalleeType->getPointeeType()));
    llvm::Value *Ret = CGF.Builder.CreateCall(MallocTy, OrigCallee.getFunctionPointer(),{SizeVal});
    switch(RetType->getSealingKind()) {
    case clang::PSK_DynamicUnsealed:
      return RValue::getComplex(Ret, EmitOtype(CGF.CGM, CGF.getContext().VoidTy));
    case clang::PSK_StaticUnsealed:
    case clang::PSK_Unsealed:
      return RValue::get(Ret);
    default:
      llvm_unreachable("Only unsealed types supported");
    }
  }
  return EmitTaggedMalloc(CGF, E->getArg(0), ArgT, RetType->getSealingKind());
}
