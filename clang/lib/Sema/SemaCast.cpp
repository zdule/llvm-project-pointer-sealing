//===--- SemaCast.cpp - Semantic Analysis for Casts -----------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
//  This file implements semantic analysis for cast expressions, including
//  1) C-style casts like '(int) x'
//  2) C++ functional casts like 'int(x)'
//  3) C++ named casts like 'static_cast<int>(x)'
//
//===----------------------------------------------------------------------===//

#include "clang/Sema/SemaInternal.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/CXXInheritance.h"
#include "clang/AST/ExprCXX.h"
#include "clang/AST/ExprObjC.h"
#include "clang/AST/RecordLayout.h"
#include "clang/AST/Attr.h"
#include "clang/Basic/PartialDiagnostic.h"
#include "clang/Basic/TargetInfo.h"
#include "clang/Lex/Preprocessor.h"
#include "clang/Sema/Initialization.h"
#include "llvm/ADT/SmallVector.h"
#include <set>
using namespace clang;



enum TryCastResult {
  TC_NotApplicable, ///< The cast method is not applicable.
  TC_Success,       ///< The cast method is appropriate and successful.
  TC_Extension,     ///< The cast method is appropriate and accepted as a
                    ///< language extension.
  TC_Failed         ///< The cast method is appropriate, but failed. A
                    ///< diagnostic has been emitted.
};

static bool isValidCast(TryCastResult TCR) {
  return TCR == TC_Success || TCR == TC_Extension;
}

enum CastType {
  CT_Const,       ///< const_cast
  CT_Static,      ///< static_cast
  CT_Reinterpret, ///< reinterpret_cast
  CT_Dynamic,     ///< dynamic_cast
  CT_CStyle,      ///< (Type)expr
  CT_Functional   ///< Type(expr)
};

static CastKind DiagnoseCapabilityToIntCast(Sema &Self, SourceRange OpRange,
                                            const Expr *E, QualType DestType);

namespace {
  struct CastOperation {
    CastOperation(Sema &S, QualType destType, ExprResult src)
      : Self(S), SrcExpr(src), DestType(destType),
        ResultType(destType.getNonLValueExprType(S.Context)),
        ValueKind(Expr::getValueKindForType(destType)),
        Kind(CK_Dependent), IsARCUnbridgedCast(false) {

      if (const BuiltinType *placeholder =
            src.get()->getType()->getAsPlaceholderType()) {
        PlaceholderKind = placeholder->getKind();
      } else {
        PlaceholderKind = (BuiltinType::Kind) 0;
      }
    }

    Sema &Self;
    ExprResult SrcExpr;
    QualType DestType;
    QualType ResultType;
    ExprValueKind ValueKind;
    CastKind Kind;
    BuiltinType::Kind PlaceholderKind;
    CXXCastPath BasePath;
    bool IsARCUnbridgedCast;

    SourceRange OpRange;
    SourceRange DestRange;

    // Top-level semantics-checking routines.
    void CheckConstCast();
    void CheckReinterpretCast();
    void CheckStaticCast();
    void CheckDynamicCast();
    void CheckCXXCStyleCast(bool FunctionalCast, bool ListInitialization);
    void CheckCStyleCast();

    void updatePartOfExplicitCastFlags(CastExpr *CE) {
      // Walk down from the CE to the OrigSrcExpr, and mark all immediate
      // ImplicitCastExpr's as being part of ExplicitCastExpr. The original CE
      // (which is a ExplicitCastExpr), and the OrigSrcExpr are not touched.
      for (; auto *ICE = dyn_cast<ImplicitCastExpr>(CE->getSubExpr()); CE = ICE)
        ICE->setIsPartOfExplicitCast(true);
    }

    /// Complete an apparently-successful cast operation that yields
    /// the given expression.
    ExprResult complete(CastExpr *castExpr) {
      SourceRange CastRange = OpRange;
      if (CXXNamedCastExpr* CNC = dyn_cast<CXXNamedCastExpr>(castExpr)) {
        CastRange = CNC->getAngleBrackets();
      }
      if (!isa<CXXConstructExpr>(SrcExpr.get())) {
        CastKind CK = DiagnoseCapabilityToIntCast(Self, CastRange,
                                                  SrcExpr.get(), DestType);
        // Make sure that the types actually match:
        if (CK == CK_CHERICapabilityToPointer && DestType->isReferenceType()) {
          // return ExprError();
        }
      }


      // If this is an unbridged cast, wrap the result in an implicit
      // cast that yields the unbridged-cast placeholder type.
      if (IsARCUnbridgedCast) {
        castExpr = ImplicitCastExpr::Create(Self.Context,
                                            Self.Context.ARCUnbridgedCastTy,
                                            CK_Dependent, castExpr, nullptr,
                                            castExpr->getValueKind());
      }
      updatePartOfExplicitCastFlags(castExpr);
      return castExpr;
    }

    // Internal convenience methods.

    /// Try to handle the given placeholder expression kind.  Return
    /// true if the source expression has the appropriate placeholder
    /// kind.  A placeholder can only be claimed once.
    bool claimPlaceholder(BuiltinType::Kind K) {
      if (PlaceholderKind != K) return false;

      PlaceholderKind = (BuiltinType::Kind) 0;
      return true;
    }

    bool isPlaceholder() const {
      return PlaceholderKind != 0;
    }
    bool isPlaceholder(BuiltinType::Kind K) const {
      return PlaceholderKind == K;
    }

    // Language specific cast restrictions for address spaces.
    void checkAddressSpaceCast(QualType SrcType, QualType DestType);

    void checkCastAlign() {
      Self.CheckCastAlign(SrcExpr.get(), DestType, OpRange);
    }

    void checkObjCConversion(Sema::CheckedConversionKind CCK) {
      assert(Self.getLangOpts().allowsNonTrivialObjCLifetimeQualifiers());

      Expr *src = SrcExpr.get();
      if (Self.CheckObjCConversion(OpRange, DestType, src, CCK) ==
          Sema::ACR_unbridged)
        IsARCUnbridgedCast = true;
      SrcExpr = src;
    }

    /// Check for and handle non-overload placeholder expressions.
    void checkNonOverloadPlaceholders() {
      if (!isPlaceholder() || isPlaceholder(BuiltinType::Overload))
        return;

      SrcExpr = Self.CheckPlaceholderExpr(SrcExpr.get());
      if (SrcExpr.isInvalid())
        return;
      PlaceholderKind = (BuiltinType::Kind) 0;
    }
  };
}

static void DiagnoseCastQual(Sema &Self, const ExprResult &SrcExpr,
                             QualType DestType);

// The Try functions attempt a specific way of casting. If they succeed, they
// return TC_Success. If their way of casting is not appropriate for the given
// arguments, they return TC_NotApplicable and *may* set diag to a diagnostic
// to emit if no other way succeeds. If their way of casting is appropriate but
// fails, they return TC_Failed and *must* set diag; they can set it to 0 if
// they emit a specialized diagnostic.
// All diagnostics returned by these functions must expect the same three
// arguments:
// %0: Cast Type (a value from the CastType enumeration)
// %1: Source Type
// %2: Destination Type
static TryCastResult TryLValueToRValueCast(Sema &Self, Expr *SrcExpr,
                                           QualType DestType, bool CStyle,
                                           CastKind &Kind,
                                           CXXCastPath &BasePath,
                                           unsigned &msg);
static TryCastResult TryStaticReferenceDowncast(Sema &Self, Expr *SrcExpr,
                                               QualType DestType, bool CStyle,
                                               SourceRange OpRange,
                                               unsigned &msg,
                                               CastKind &Kind,
                                               CXXCastPath &BasePath);
static TryCastResult TryStaticPointerDowncast(Sema &Self, QualType SrcType,
                                              QualType DestType, bool CStyle,
                                              SourceRange OpRange,
                                              unsigned &msg,
                                              CastKind &Kind,
                                              CXXCastPath &BasePath);
static TryCastResult TryStaticDowncast(Sema &Self, CanQualType SrcType,
                                       CanQualType DestType, bool CStyle,
                                       SourceRange OpRange,
                                       QualType OrigSrcType,
                                       QualType OrigDestType, unsigned &msg,
                                       CastKind &Kind,
                                       CXXCastPath &BasePath);
static TryCastResult TryStaticMemberPointerUpcast(Sema &Self, ExprResult &SrcExpr,
                                               QualType SrcType,
                                               QualType DestType,bool CStyle,
                                               SourceRange OpRange,
                                               unsigned &msg,
                                               CastKind &Kind,
                                               CXXCastPath &BasePath);

static TryCastResult TryStaticImplicitCast(Sema &Self, ExprResult &SrcExpr,
                                           QualType DestType,
                                           Sema::CheckedConversionKind CCK,
                                           SourceRange OpRange,
                                           unsigned &msg, CastKind &Kind,
                                           bool ListInitialization);
static TryCastResult TryStaticCast(Sema &Self, ExprResult &SrcExpr,
                                   QualType DestType,
                                   Sema::CheckedConversionKind CCK,
                                   SourceRange OpRange,
                                   unsigned &msg, CastKind &Kind,
                                   CXXCastPath &BasePath,
                                   bool ListInitialization);
static TryCastResult TryConstCast(Sema &Self, ExprResult &SrcExpr,
                                  QualType DestType, bool CStyle,
                                  unsigned &msg);
static TryCastResult TryReinterpretCast(Sema &Self, ExprResult &SrcExpr,
                                        QualType DestType, bool CStyle,
                                        SourceRange OpRange,
                                        unsigned &msg,
                                        CastKind &Kind);


/// ActOnCXXNamedCast - Parse {dynamic,static,reinterpret,const}_cast's.
ExprResult
Sema::ActOnCXXNamedCast(SourceLocation OpLoc, tok::TokenKind Kind,
                        SourceLocation LAngleBracketLoc, Declarator &D,
                        SourceLocation RAngleBracketLoc,
                        SourceLocation LParenLoc, Expr *E,
                        SourceLocation RParenLoc) {

  assert(!D.isInvalidType());

  TypeSourceInfo *TInfo = GetTypeForDeclaratorCast(D, E->getType());
  if (D.isInvalidType())
    return ExprError();

  if (getLangOpts().CPlusPlus) {
    // Check that there are no default arguments (C++ only).
    CheckExtraCXXDefaultArguments(D);
  }

  return BuildCXXNamedCast(OpLoc, Kind, TInfo, E,
                           SourceRange(LAngleBracketLoc, RAngleBracketLoc),
                           SourceRange(LParenLoc, RParenLoc));
}

ExprResult
Sema::BuildCXXNamedCast(SourceLocation OpLoc, tok::TokenKind Kind,
                        TypeSourceInfo *DestTInfo, Expr *E,
                        SourceRange AngleBrackets, SourceRange Parens) {
  ExprResult Ex = E;
  QualType DestType = DestTInfo->getType();

  // If the type is dependent, we won't do the semantic analysis now.
  bool TypeDependent =
      DestType->isDependentType() || Ex.get()->isTypeDependent();

  CastOperation Op(*this, DestType, E);
  Op.OpRange = SourceRange(OpLoc, Parens.getEnd());
  Op.DestRange = AngleBrackets;

  switch (Kind) {
  default: llvm_unreachable("Unknown C++ cast!");

  case tok::kw_const_cast:
    if (!TypeDependent) {
      Op.CheckConstCast();
      if (Op.SrcExpr.isInvalid())
        return ExprError();
      DiscardMisalignedMemberAddress(DestType.getTypePtr(), E);
    }
    return Op.complete(CXXConstCastExpr::Create(Context, Op.ResultType,
                                  Op.ValueKind, Op.SrcExpr.get(), DestTInfo,
                                                OpLoc, Parens.getEnd(),
                                                AngleBrackets));

  case tok::kw_dynamic_cast: {
    // OpenCL C++ 1.0 s2.9: dynamic_cast is not supported.
    if (getLangOpts().OpenCLCPlusPlus) {
      return ExprError(Diag(OpLoc, diag::err_openclcxx_not_supported)
                       << "dynamic_cast");
    }

    if (!TypeDependent) {
      Op.CheckDynamicCast();
      if (Op.SrcExpr.isInvalid())
        return ExprError();
    }
    return Op.complete(CXXDynamicCastExpr::Create(Context, Op.ResultType,
                                    Op.ValueKind, Op.Kind, Op.SrcExpr.get(),
                                                  &Op.BasePath, DestTInfo,
                                                  OpLoc, Parens.getEnd(),
                                                  AngleBrackets));
  }
  case tok::kw_reinterpret_cast: {
    if (!TypeDependent) {
      Op.CheckReinterpretCast();
      if (Op.SrcExpr.isInvalid())
        return ExprError();
      DiscardMisalignedMemberAddress(DestType.getTypePtr(), E);
    }
    return Op.complete(CXXReinterpretCastExpr::Create(Context, Op.ResultType,
                                    Op.ValueKind, Op.Kind, Op.SrcExpr.get(),
                                                      nullptr, DestTInfo, OpLoc,
                                                      Parens.getEnd(),
                                                      AngleBrackets));
  }
  case tok::kw_static_cast: {
    if (!TypeDependent) {
      Op.CheckStaticCast();
      if (Op.SrcExpr.isInvalid())
        return ExprError();
      DiscardMisalignedMemberAddress(DestType.getTypePtr(), E);
    }

    return Op.complete(CXXStaticCastExpr::Create(Context, Op.ResultType,
                                   Op.ValueKind, Op.Kind, Op.SrcExpr.get(),
                                                 &Op.BasePath, DestTInfo,
                                                 OpLoc, Parens.getEnd(),
                                                 AngleBrackets));
  }
  }
}

/// Try to diagnose a failed overloaded cast.  Returns true if
/// diagnostics were emitted.
static bool tryDiagnoseOverloadedCast(Sema &S, CastType CT,
                                      SourceRange range, Expr *src,
                                      QualType destType,
                                      bool listInitialization) {
  switch (CT) {
  // These cast kinds don't consider user-defined conversions.
  case CT_Const:
  case CT_Reinterpret:
  case CT_Dynamic:
    return false;

  // These do.
  case CT_Static:
  case CT_CStyle:
  case CT_Functional:
    break;
  }

  QualType srcType = src->getType();
  if (!destType->isRecordType() && !srcType->isRecordType())
    return false;

  InitializedEntity entity = InitializedEntity::InitializeTemporary(destType);
  InitializationKind initKind
    = (CT == CT_CStyle)? InitializationKind::CreateCStyleCast(range.getBegin(),
                                                      range, listInitialization)
    : (CT == CT_Functional)? InitializationKind::CreateFunctionalCast(range,
                                                             listInitialization)
    : InitializationKind::CreateCast(/*type range?*/ range);
  InitializationSequence sequence(S, entity, initKind, src);

  assert(sequence.Failed() && "initialization succeeded on second try?");
  switch (sequence.getFailureKind()) {
  default: return false;

  case InitializationSequence::FK_ConstructorOverloadFailed:
  case InitializationSequence::FK_UserConversionOverloadFailed:
    break;
  }

  OverloadCandidateSet &candidates = sequence.getFailedCandidateSet();

  unsigned msg = 0;
  OverloadCandidateDisplayKind howManyCandidates = OCD_AllCandidates;

  switch (sequence.getFailedOverloadResult()) {
  case OR_Success: llvm_unreachable("successful failed overload");
  case OR_No_Viable_Function:
    if (candidates.empty())
      msg = diag::err_ovl_no_conversion_in_cast;
    else
      msg = diag::err_ovl_no_viable_conversion_in_cast;
    howManyCandidates = OCD_AllCandidates;
    break;

  case OR_Ambiguous:
    msg = diag::err_ovl_ambiguous_conversion_in_cast;
    howManyCandidates = OCD_ViableCandidates;
    break;

  case OR_Deleted:
    msg = diag::err_ovl_deleted_conversion_in_cast;
    howManyCandidates = OCD_ViableCandidates;
    break;
  }

  S.Diag(range.getBegin(), msg)
    << CT << srcType << destType
    << range << src->getSourceRange();

  candidates.NoteCandidates(S, howManyCandidates, src);

  return true;
}

/// Diagnose a failed cast.
static void diagnoseBadCast(Sema &S, unsigned msg, CastType castType,
                            SourceRange opRange, Expr *src, QualType destType,
                            bool listInitialization) {
  if (msg == diag::err_bad_cxx_cast_generic &&
      tryDiagnoseOverloadedCast(S, castType, opRange, src, destType,
                                listInitialization))
    return;

  S.Diag(opRange.getBegin(), msg) << castType
    << src->getType() << destType << opRange << src->getSourceRange();

  // Detect if both types are (ptr to) class, and note any incompleteness.
  int DifferentPtrness = 0;
  QualType From = destType;
  if (auto Ptr = From->getAs<PointerType>()) {
    From = Ptr->getPointeeType();
    DifferentPtrness++;
  }
  QualType To = src->getType();
  if (auto Ptr = To->getAs<PointerType>()) {
    To = Ptr->getPointeeType();
    DifferentPtrness--;
  }
  if (!DifferentPtrness) {
    auto RecFrom = From->getAs<RecordType>();
    auto RecTo = To->getAs<RecordType>();
    if (RecFrom && RecTo) {
      auto DeclFrom = RecFrom->getAsCXXRecordDecl();
      if (!DeclFrom->isCompleteDefinition())
        S.Diag(DeclFrom->getLocation(), diag::note_type_incomplete)
          << DeclFrom->getDeclName();
      auto DeclTo = RecTo->getAsCXXRecordDecl();
      if (!DeclTo->isCompleteDefinition())
        S.Diag(DeclTo->getLocation(), diag::note_type_incomplete)
          << DeclTo->getDeclName();
    }
  }
}

namespace {
/// The kind of unwrapping we did when determining whether a conversion casts
/// away constness.
enum CastAwayConstnessKind {
  /// The conversion does not cast away constness.
  CACK_None = 0,
  /// We unwrapped similar types.
  CACK_Similar = 1,
  /// We unwrapped dissimilar types with similar representations (eg, a pointer
  /// versus an Objective-C object pointer).
  CACK_SimilarKind = 2,
  /// We unwrapped representationally-unrelated types, such as a pointer versus
  /// a pointer-to-member.
  CACK_Incoherent = 3,
};
}

/// Unwrap one level of types for CastsAwayConstness.
///
/// Like Sema::UnwrapSimilarTypes, this removes one level of indirection from
/// both types, provided that they're both pointer-like or array-like. Unlike
/// the Sema function, doesn't care if the unwrapped pieces are related.
///
/// This function may remove additional levels as necessary for correctness:
/// the resulting T1 is unwrapped sufficiently that it is never an array type,
/// so that its qualifiers can be directly compared to those of T2 (which will
/// have the combined set of qualifiers from all indermediate levels of T2),
/// as (effectively) required by [expr.const.cast]p7 replacing T1's qualifiers
/// with those from T2.
static CastAwayConstnessKind
unwrapCastAwayConstnessLevel(ASTContext &Context, QualType &T1, QualType &T2) {
  enum { None, Ptr, MemPtr, BlockPtr, Array };
  auto Classify = [](QualType T) {
    if (T->isAnyPointerType()) return Ptr;
    if (T->isMemberPointerType()) return MemPtr;
    if (T->isBlockPointerType()) return BlockPtr;
    // We somewhat-arbitrarily don't look through VLA types here. This is at
    // least consistent with the behavior of UnwrapSimilarTypes.
    if (T->isConstantArrayType() || T->isIncompleteArrayType()) return Array;
    return None;
  };

  auto Unwrap = [&](QualType T) {
    if (auto *AT = Context.getAsArrayType(T))
      return AT->getElementType();
    return T->getPointeeType();
  };

  CastAwayConstnessKind Kind;

  if (T2->isReferenceType()) {
    // Special case: if the destination type is a reference type, unwrap it as
    // the first level. (The source will have been an lvalue expression in this
    // case, so there is no corresponding "reference to" in T1 to remove.) This
    // simulates removing a "pointer to" from both sides.
    T2 = T2->getPointeeType();
    Kind = CastAwayConstnessKind::CACK_Similar;
  } else if (Context.UnwrapSimilarTypes(T1, T2)) {
    Kind = CastAwayConstnessKind::CACK_Similar;
  } else {
    // Try unwrapping mismatching levels.
    int T1Class = Classify(T1);
    if (T1Class == None)
      return CastAwayConstnessKind::CACK_None;

    int T2Class = Classify(T2);
    if (T2Class == None)
      return CastAwayConstnessKind::CACK_None;

    T1 = Unwrap(T1);
    T2 = Unwrap(T2);
    Kind = T1Class == T2Class ? CastAwayConstnessKind::CACK_SimilarKind
                              : CastAwayConstnessKind::CACK_Incoherent;
  }

  // We've unwrapped at least one level. If the resulting T1 is a (possibly
  // multidimensional) array type, any qualifier on any matching layer of
  // T2 is considered to correspond to T1. Decompose down to the element
  // type of T1 so that we can compare properly.
  while (true) {
    Context.UnwrapSimilarArrayTypes(T1, T2);

    if (Classify(T1) != Array)
      break;

    auto T2Class = Classify(T2);
    if (T2Class == None)
      break;

    if (T2Class != Array)
      Kind = CastAwayConstnessKind::CACK_Incoherent;
    else if (Kind != CastAwayConstnessKind::CACK_Incoherent)
      Kind = CastAwayConstnessKind::CACK_SimilarKind;

    T1 = Unwrap(T1);
    T2 = Unwrap(T2).withCVRQualifiers(T2.getCVRQualifiers());
  }

  return Kind;
}

/// Check if the pointer conversion from SrcType to DestType casts away
/// constness as defined in C++ [expr.const.cast]. This is used by the cast
/// checkers. Both arguments must denote pointer (possibly to member) types.
///
/// \param CheckCVR Whether to check for const/volatile/restrict qualifiers.
/// \param CheckObjCLifetime Whether to check Objective-C lifetime qualifiers.
static CastAwayConstnessKind
CastsAwayConstness(Sema &Self, QualType SrcType, QualType DestType,
                   bool CheckCVR, bool CheckObjCLifetime,
                   QualType *TheOffendingSrcType = nullptr,
                   QualType *TheOffendingDestType = nullptr,
                   Qualifiers *CastAwayQualifiers = nullptr) {
  // If the only checking we care about is for Objective-C lifetime qualifiers,
  // and we're not in ObjC mode, there's nothing to check.
  if (!CheckCVR && CheckObjCLifetime && !Self.Context.getLangOpts().ObjC)
    return CastAwayConstnessKind::CACK_None;

  if (!DestType->isReferenceType()) {
    assert((SrcType->isAnyPointerType() || SrcType->isMemberPointerType() ||
            SrcType->isBlockPointerType()) &&
           "Source type is not pointer or pointer to member.");
    assert((DestType->isAnyPointerType() || DestType->isMemberPointerType() ||
            DestType->isBlockPointerType()) &&
           "Destination type is not pointer or pointer to member.");
  }

  QualType UnwrappedSrcType = Self.Context.getCanonicalType(SrcType),
           UnwrappedDestType = Self.Context.getCanonicalType(DestType);

  // Find the qualifiers. We only care about cvr-qualifiers for the
  // purpose of this check, because other qualifiers (address spaces,
  // Objective-C GC, etc.) are part of the type's identity.
  QualType PrevUnwrappedSrcType = UnwrappedSrcType;
  QualType PrevUnwrappedDestType = UnwrappedDestType;
  auto WorstKind = CastAwayConstnessKind::CACK_Similar;
  bool AllConstSoFar = true;
  while (auto Kind = unwrapCastAwayConstnessLevel(
             Self.Context, UnwrappedSrcType, UnwrappedDestType)) {
    // Track the worst kind of unwrap we needed to do before we found a
    // problem.
    if (Kind > WorstKind)
      WorstKind = Kind;

    // Determine the relevant qualifiers at this level.
    Qualifiers SrcQuals, DestQuals;
    Self.Context.getUnqualifiedArrayType(UnwrappedSrcType, SrcQuals);
    Self.Context.getUnqualifiedArrayType(UnwrappedDestType, DestQuals);

    // We do not meaningfully track object const-ness of Objective-C object
    // types. Remove const from the source type if either the source or
    // the destination is an Objective-C object type.
    if (UnwrappedSrcType->isObjCObjectType() ||
        UnwrappedDestType->isObjCObjectType())
      SrcQuals.removeConst();

    if (CheckCVR) {
      Qualifiers SrcCvrQuals =
          Qualifiers::fromCVRMask(SrcQuals.getCVRQualifiers());
      Qualifiers DestCvrQuals =
          Qualifiers::fromCVRMask(DestQuals.getCVRQualifiers());

      if (SrcCvrQuals != DestCvrQuals) {
        if (CastAwayQualifiers)
          *CastAwayQualifiers = SrcCvrQuals - DestCvrQuals;

        // If we removed a cvr-qualifier, this is casting away 'constness'.
        if (!DestCvrQuals.compatiblyIncludes(SrcCvrQuals)) {
          if (TheOffendingSrcType)
            *TheOffendingSrcType = PrevUnwrappedSrcType;
          if (TheOffendingDestType)
            *TheOffendingDestType = PrevUnwrappedDestType;
          return WorstKind;
        }

        // If any prior level was not 'const', this is also casting away
        // 'constness'. We noted the outermost type missing a 'const' already.
        if (!AllConstSoFar)
          return WorstKind;
      }
    }

    if (CheckObjCLifetime &&
        !DestQuals.compatiblyIncludesObjCLifetime(SrcQuals))
      return WorstKind;

    // If we found our first non-const-qualified type, this may be the place
    // where things start to go wrong.
    if (AllConstSoFar && !DestQuals.hasConst()) {
      AllConstSoFar = false;
      if (TheOffendingSrcType)
        *TheOffendingSrcType = PrevUnwrappedSrcType;
      if (TheOffendingDestType)
        *TheOffendingDestType = PrevUnwrappedDestType;
    }

    PrevUnwrappedSrcType = UnwrappedSrcType;
    PrevUnwrappedDestType = UnwrappedDestType;
  }

  return CastAwayConstnessKind::CACK_None;
}

static TryCastResult getCastAwayConstnessCastKind(CastAwayConstnessKind CACK,
                                                  unsigned &DiagID) {
  switch (CACK) {
  case CastAwayConstnessKind::CACK_None:
    llvm_unreachable("did not cast away constness");

  case CastAwayConstnessKind::CACK_Similar:
    // FIXME: Accept these as an extension too?
  case CastAwayConstnessKind::CACK_SimilarKind:
    DiagID = diag::err_bad_cxx_cast_qualifiers_away;
    return TC_Failed;

  case CastAwayConstnessKind::CACK_Incoherent:
    DiagID = diag::ext_bad_cxx_cast_qualifiers_away_incoherent;
    return TC_Extension;
  }

  llvm_unreachable("unexpected cast away constness kind");
}

static bool IsBadCheriReferenceCast(const ReferenceType *Dest, Expr *SrcExpr,
                                    ASTContext &Ctx) {
  if (Ctx.getLangOpts().getCheriCapConversion() == LangOptions::CapConv_Ignore)
    return false;
  bool SrcIsCapRef = Ctx.getTargetInfo().areAllPointersCapabilities();
  if (auto SrcRef = SrcExpr->getRealReferenceType(Ctx)->getAs<ReferenceType>())
    SrcIsCapRef = SrcRef->isCHERICapability();
  return Dest->isCHERICapability() != SrcIsCapRef;
}

/// CheckDynamicCast - Check that a dynamic_cast\<DestType\>(SrcExpr) is valid.
/// Refer to C++ 5.2.7 for details. Dynamic casts are used mostly for runtime-
/// checked downcasts in class hierarchies.
void CastOperation::CheckDynamicCast() {
  if (ValueKind == VK_RValue)
    SrcExpr = Self.DefaultFunctionArrayLvalueConversion(SrcExpr.get());
  else if (isPlaceholder())
    SrcExpr = Self.CheckPlaceholderExpr(SrcExpr.get());
  if (SrcExpr.isInvalid()) // if conversion failed, don't report another error
    return;

  QualType OrigSrcType = SrcExpr.get()->getType();
  QualType DestType = Self.Context.getCanonicalType(this->DestType);

  // C++ 5.2.7p1: T shall be a pointer or reference to a complete class type,
  //   or "pointer to cv void".

  QualType DestPointee;
  const PointerType *DestPointer = DestType->getAs<PointerType>();
  const ReferenceType *DestReference = nullptr;
  if (DestPointer) {
    DestPointee = DestPointer->getPointeeType();
  } else if ((DestReference = DestType->getAs<ReferenceType>())) {
    DestPointee = DestReference->getPointeeType();
  } else {
    Self.Diag(OpRange.getBegin(), diag::err_bad_dynamic_cast_not_ref_or_ptr)
        << this->DestType << DestRange;
    SrcExpr = ExprError();
    return;
  }

  const RecordType *DestRecord = DestPointee->getAs<RecordType>();
  if (DestPointee->isVoidType()) {
    assert(DestPointer && "Reference to void is not possible");
  } else if (DestRecord) {
    if (Self.RequireCompleteType(OpRange.getBegin(), DestPointee,
                                 diag::err_bad_dynamic_cast_incomplete,
                                 DestRange)) {
      SrcExpr = ExprError();
      return;
    }
  } else {
    Self.Diag(OpRange.getBegin(), diag::err_bad_dynamic_cast_not_class)
      << DestPointee.getUnqualifiedType() << DestRange;
    SrcExpr = ExprError();
    return;
  }

  // C++0x 5.2.7p2: If T is a pointer type, v shall be an rvalue of a pointer to
  //   complete class type, [...]. If T is an lvalue reference type, v shall be
  //   an lvalue of a complete class type, [...]. If T is an rvalue reference
  //   type, v shall be an expression having a complete class type, [...]
  QualType SrcType = Self.Context.getCanonicalType(OrigSrcType);
  QualType SrcPointee;
  if (DestPointer) {
    if (const PointerType *SrcPointer = SrcType->getAs<PointerType>()) {
      SrcPointee = SrcPointer->getPointeeType();
    } else {
      Self.Diag(OpRange.getBegin(), diag::err_bad_dynamic_cast_not_ptr)
        << OrigSrcType << SrcExpr.get()->getSourceRange();
      SrcExpr = ExprError();
      return;
    }
  } else if (DestReference->isLValueReferenceType()) {
    if (!SrcExpr.get()->isLValue()) {
      Self.Diag(OpRange.getBegin(), diag::err_bad_cxx_cast_rvalue)
        << CT_Dynamic << OrigSrcType << this->DestType << OpRange;
    }
    SrcPointee = SrcType;
  } else {
    // If we're dynamic_casting from a prvalue to an rvalue reference, we need
    // to materialize the prvalue before we bind the reference to it.
    if (SrcExpr.get()->isRValue())
      SrcExpr = Self.CreateMaterializeTemporaryExpr(
          SrcType, SrcExpr.get(), /*IsLValueReference*/ false);
    SrcPointee = SrcType;
  }

  const RecordType *SrcRecord = SrcPointee->getAs<RecordType>();
  if (SrcRecord) {
    if (Self.RequireCompleteType(OpRange.getBegin(), SrcPointee,
                                 diag::err_bad_dynamic_cast_incomplete,
                                 SrcExpr.get())) {
      SrcExpr = ExprError();
      return;
    }
  } else {
    Self.Diag(OpRange.getBegin(), diag::err_bad_dynamic_cast_not_class)
      << SrcPointee.getUnqualifiedType() << SrcExpr.get()->getSourceRange();
    SrcExpr = ExprError();
    return;
  }

  assert((DestPointer || DestReference) &&
    "Bad destination non-ptr/ref slipped through.");
  assert((DestRecord || DestPointee->isVoidType()) &&
    "Bad destination pointee slipped through.");
  assert(SrcRecord && "Bad source pointee slipped through.");

  // C++ 5.2.7p1: The dynamic_cast operator shall not cast away constness.
  if (!DestPointee.isAtLeastAsQualifiedAs(SrcPointee)) {
    Self.Diag(OpRange.getBegin(), diag::err_bad_cxx_cast_qualifiers_away)
      << CT_Dynamic << OrigSrcType << this->DestType << OpRange;
    SrcExpr = ExprError();
    return;
  }

  // Check that the dynamic cast doesn't change the capability qualifier
  if (DestReference && IsBadCheriReferenceCast(DestReference, SrcExpr.get(),
                                               Self.getASTContext())) {
    Self.Diag(OpRange.getBegin(), diag::err_bad_cxx_reference_cast_capability_qualifier)
            << CT_Dynamic << 0 << DestType;
    SrcExpr = ExprError();
    return;
  }

  // C++ 5.2.7p3: If the type of v is the same as the required result type,
  //   [except for cv].
  if (DestRecord == SrcRecord) {
    Kind = CK_NoOp;
    return;
  }

  // C++ 5.2.7p5
  // Upcasts are resolved statically.
  if (DestRecord &&
      Self.IsDerivedFrom(OpRange.getBegin(), SrcPointee, DestPointee)) {
    if (Self.CheckDerivedToBaseConversion(SrcPointee, DestPointee,
                                           OpRange.getBegin(), OpRange,
                                           &BasePath)) {
      SrcExpr = ExprError();
      return;
    }

    Kind = CK_DerivedToBase;
    return;
  }

  // C++ 5.2.7p6: Otherwise, v shall be [polymorphic].
  const RecordDecl *SrcDecl = SrcRecord->getDecl()->getDefinition();
  assert(SrcDecl && "Definition missing");
  if (!cast<CXXRecordDecl>(SrcDecl)->isPolymorphic()) {
    Self.Diag(OpRange.getBegin(), diag::err_bad_dynamic_cast_not_polymorphic)
      << SrcPointee.getUnqualifiedType() << SrcExpr.get()->getSourceRange();
    SrcExpr = ExprError();
  }

  // dynamic_cast is not available with -fno-rtti.
  // As an exception, dynamic_cast to void* is available because it doesn't
  // use RTTI.
  if (!Self.getLangOpts().RTTI && !DestPointee->isVoidType()) {
    Self.Diag(OpRange.getBegin(), diag::err_no_dynamic_cast_with_fno_rtti);
    SrcExpr = ExprError();
    return;
  }

  // Done. Everything else is run-time checks.
  Kind = CK_Dynamic;
}

/// CheckConstCast - Check that a const_cast\<DestType\>(SrcExpr) is valid.
/// Refer to C++ 5.2.11 for details. const_cast is typically used in code
/// like this:
/// const char *str = "literal";
/// legacy_function(const_cast\<char*\>(str));
void CastOperation::CheckConstCast() {
  if (ValueKind == VK_RValue)
    SrcExpr = Self.DefaultFunctionArrayLvalueConversion(SrcExpr.get());
  else if (isPlaceholder())
    SrcExpr = Self.CheckPlaceholderExpr(SrcExpr.get());
  if (SrcExpr.isInvalid()) // if conversion failed, don't report another error
    return;

  unsigned msg = diag::err_bad_cxx_cast_generic;
  auto TCR = TryConstCast(Self, SrcExpr, DestType, /*CStyle*/ false, msg);
  if (TCR != TC_Success && msg != 0) {
    Self.Diag(OpRange.getBegin(), msg) << CT_Const
      << SrcExpr.get()->getType() << DestType << OpRange;
  }
  if (!isValidCast(TCR))
    SrcExpr = ExprError();
}

/// Check that a reinterpret_cast\<DestType\>(SrcExpr) is not used as upcast
/// or downcast between respective pointers or references.
static void DiagnoseReinterpretUpDownCast(Sema &Self, const Expr *SrcExpr,
                                          QualType DestType,
                                          SourceRange OpRange) {
  QualType SrcType = SrcExpr->getType();
  // When casting from pointer or reference, get pointee type; use original
  // type otherwise.
  const CXXRecordDecl *SrcPointeeRD = SrcType->getPointeeCXXRecordDecl();
  const CXXRecordDecl *SrcRD =
    SrcPointeeRD ? SrcPointeeRD : SrcType->getAsCXXRecordDecl();

  // Examining subobjects for records is only possible if the complete and
  // valid definition is available.  Also, template instantiation is not
  // allowed here.
  if (!SrcRD || !SrcRD->isCompleteDefinition() || SrcRD->isInvalidDecl())
    return;

  const CXXRecordDecl *DestRD = DestType->getPointeeCXXRecordDecl();

  if (!DestRD || !DestRD->isCompleteDefinition() || DestRD->isInvalidDecl())
    return;

  enum {
    ReinterpretUpcast,
    ReinterpretDowncast
  } ReinterpretKind;

  CXXBasePaths BasePaths;

  if (SrcRD->isDerivedFrom(DestRD, BasePaths))
    ReinterpretKind = ReinterpretUpcast;
  else if (DestRD->isDerivedFrom(SrcRD, BasePaths))
    ReinterpretKind = ReinterpretDowncast;
  else
    return;

  bool VirtualBase = true;
  bool NonZeroOffset = false;
  for (CXXBasePaths::const_paths_iterator I = BasePaths.begin(),
                                          E = BasePaths.end();
       I != E; ++I) {
    const CXXBasePath &Path = *I;
    CharUnits Offset = CharUnits::Zero();
    bool IsVirtual = false;
    for (CXXBasePath::const_iterator IElem = Path.begin(), EElem = Path.end();
         IElem != EElem; ++IElem) {
      IsVirtual = IElem->Base->isVirtual();
      if (IsVirtual)
        break;
      const CXXRecordDecl *BaseRD = IElem->Base->getType()->getAsCXXRecordDecl();
      assert(BaseRD && "Base type should be a valid unqualified class type");
      // Don't check if any base has invalid declaration or has no definition
      // since it has no layout info.
      const CXXRecordDecl *Class = IElem->Class,
                          *ClassDefinition = Class->getDefinition();
      if (Class->isInvalidDecl() || !ClassDefinition ||
          !ClassDefinition->isCompleteDefinition())
        return;

      const ASTRecordLayout &DerivedLayout =
          Self.Context.getASTRecordLayout(Class);
      Offset += DerivedLayout.getBaseClassOffset(BaseRD);
    }
    if (!IsVirtual) {
      // Don't warn if any path is a non-virtually derived base at offset zero.
      if (Offset.isZero())
        return;
      // Offset makes sense only for non-virtual bases.
      else
        NonZeroOffset = true;
    }
    VirtualBase = VirtualBase && IsVirtual;
  }

  (void) NonZeroOffset; // Silence set but not used warning.
  assert((VirtualBase || NonZeroOffset) &&
         "Should have returned if has non-virtual base with zero offset");

  QualType BaseType =
      ReinterpretKind == ReinterpretUpcast? DestType : SrcType;
  QualType DerivedType =
      ReinterpretKind == ReinterpretUpcast? SrcType : DestType;

  SourceLocation BeginLoc = OpRange.getBegin();
  Self.Diag(BeginLoc, diag::warn_reinterpret_different_from_static)
    << DerivedType << BaseType << !VirtualBase << int(ReinterpretKind)
    << OpRange;
  Self.Diag(BeginLoc, diag::note_reinterpret_updowncast_use_static)
    << int(ReinterpretKind)
    << FixItHint::CreateReplacement(BeginLoc, "static_cast");
}

/// CheckReinterpretCast - Check that a reinterpret_cast\<DestType\>(SrcExpr) is
/// valid.
/// Refer to C++ 5.2.10 for details. reinterpret_cast is typically used in code
/// like this:
/// char *bytes = reinterpret_cast\<char*\>(int_ptr);
void CastOperation::CheckReinterpretCast() {
  if (ValueKind == VK_RValue && !isPlaceholder(BuiltinType::Overload))
    SrcExpr = Self.DefaultFunctionArrayLvalueConversion(SrcExpr.get());
  else
    checkNonOverloadPlaceholders();
  if (SrcExpr.isInvalid()) // if conversion failed, don't report another error
    return;

  unsigned msg = diag::err_bad_cxx_cast_generic;
  TryCastResult tcr =
    TryReinterpretCast(Self, SrcExpr, DestType,
                       /*CStyle*/false, OpRange, msg, Kind);
  if (tcr != TC_Success && msg != 0) {
    if (SrcExpr.isInvalid()) // if conversion failed, don't report another error
      return;
    if (SrcExpr.get()->getType() == Self.Context.OverloadTy) {
      //FIXME: &f<int>; is overloaded and resolvable
      Self.Diag(OpRange.getBegin(), diag::err_bad_reinterpret_cast_overload)
        << OverloadExpr::find(SrcExpr.get()).Expression->getName()
        << DestType << OpRange;
      Self.NoteAllOverloadCandidates(SrcExpr.get());

    } else {
      diagnoseBadCast(Self, msg, CT_Reinterpret, OpRange, SrcExpr.get(),
                      DestType, /*listInitialization=*/false);
    }
  }

  if (isValidCast(tcr)) {
    if (Self.getLangOpts().allowsNonTrivialObjCLifetimeQualifiers())
      checkObjCConversion(Sema::CCK_OtherCast);
    DiagnoseReinterpretUpDownCast(Self, SrcExpr.get(), DestType, OpRange);
  } else {
    SrcExpr = ExprError();
  }
}


/// CheckStaticCast - Check that a static_cast\<DestType\>(SrcExpr) is valid.
/// Refer to C++ 5.2.9 for details. Static casts are mostly used for making
/// implicit conversions explicit and getting rid of data loss warnings.
void CastOperation::CheckStaticCast() {
  if (isPlaceholder()) {
    checkNonOverloadPlaceholders();
    if (SrcExpr.isInvalid())
      return;
  }

  // This test is outside everything else because it's the only case where
  // a non-lvalue-reference target type does not lead to decay.
  // C++ 5.2.9p4: Any expression can be explicitly converted to type "cv void".
  if (DestType->isVoidType()) {
    Kind = CK_ToVoid;

    if (claimPlaceholder(BuiltinType::Overload)) {
      Self.ResolveAndFixSingleFunctionTemplateSpecialization(SrcExpr,
                false, // Decay Function to ptr
                true, // Complain
                OpRange, DestType, diag::err_bad_static_cast_overload);
      if (SrcExpr.isInvalid())
        return;
    }

    SrcExpr = Self.IgnoredValueConversions(SrcExpr.get());
    return;
  }

  if (ValueKind == VK_RValue && !DestType->isRecordType() &&
      !isPlaceholder(BuiltinType::Overload)) {
    SrcExpr = Self.DefaultFunctionArrayLvalueConversion(SrcExpr.get());
    if (SrcExpr.isInvalid()) // if conversion failed, don't report another error
      return;
  }

  unsigned msg = diag::err_bad_cxx_cast_generic;
  TryCastResult tcr
    = TryStaticCast(Self, SrcExpr, DestType, Sema::CCK_OtherCast, OpRange, msg,
                    Kind, BasePath, /*ListInitialization=*/false);
  if (tcr != TC_Success && msg != 0) {
    if (SrcExpr.isInvalid())
      return;
    if (SrcExpr.get()->getType() == Self.Context.OverloadTy) {
      OverloadExpr* oe = OverloadExpr::find(SrcExpr.get()).Expression;
      Self.Diag(OpRange.getBegin(), diag::err_bad_static_cast_overload)
        << oe->getName() << DestType << OpRange
        << oe->getQualifierLoc().getSourceRange();
      Self.NoteAllOverloadCandidates(SrcExpr.get());
    } else {
      diagnoseBadCast(Self, msg, CT_Static, OpRange, SrcExpr.get(), DestType,
                      /*listInitialization=*/false);
    }
  }

  if (isValidCast(tcr)) {
    if (Kind == CK_BitCast)
      checkCastAlign();
    if (Self.getLangOpts().allowsNonTrivialObjCLifetimeQualifiers())
      checkObjCConversion(Sema::CCK_OtherCast);
  } else {
    SrcExpr = ExprError();
  }
}

static bool IsAddressSpaceConversion(QualType SrcType, QualType DestType) {
  auto *SrcPtrType = SrcType->getAs<PointerType>();
  if (!SrcPtrType)
    return false;
  auto *DestPtrType = DestType->getAs<PointerType>();
  if (!DestPtrType)
    return false;
  return SrcPtrType->getPointeeType().getAddressSpace() !=
         DestPtrType->getPointeeType().getAddressSpace();
}

/// TryStaticCast - Check if a static cast can be performed, and do so if
/// possible. If @p CStyle, ignore access restrictions on hierarchy casting
/// and casting away constness.
static TryCastResult TryStaticCast(Sema &Self, ExprResult &SrcExpr,
                                   QualType DestType,
                                   Sema::CheckedConversionKind CCK,
                                   SourceRange OpRange, unsigned &msg,
                                   CastKind &Kind, CXXCastPath &BasePath,
                                   bool ListInitialization) {
  // Determine whether we have the semantics of a C-style cast.
  bool CStyle
    = (CCK == Sema::CCK_CStyleCast || CCK == Sema::CCK_FunctionalCast);

  // The order the tests is not entirely arbitrary. There is one conversion
  // that can be handled in two different ways. Given:
  // struct A {};
  // struct B : public A {
  //   B(); B(const A&);
  // };
  // const A &a = B();
  // the cast static_cast<const B&>(a) could be seen as either a static
  // reference downcast, or an explicit invocation of the user-defined
  // conversion using B's conversion constructor.
  // DR 427 specifies that the downcast is to be applied here.

  // C++ 5.2.9p4: Any expression can be explicitly converted to type "cv void".
  // Done outside this function.

  TryCastResult tcr;

  // C++ 5.2.9p5, reference downcast.
  // See the function for details.
  // DR 427 specifies that this is to be applied before paragraph 2.
  tcr = TryStaticReferenceDowncast(Self, SrcExpr.get(), DestType, CStyle,
                                   OpRange, msg, Kind, BasePath);
  if (tcr != TC_NotApplicable)
    return tcr;

  // C++11 [expr.static.cast]p3:
  //   A glvalue of type "cv1 T1" can be cast to type "rvalue reference to cv2
  //   T2" if "cv2 T2" is reference-compatible with "cv1 T1".
  tcr = TryLValueToRValueCast(Self, SrcExpr.get(), DestType, CStyle, Kind,
                              BasePath, msg);
  if (tcr != TC_NotApplicable)
    return tcr;

  // C++ 5.2.9p2: An expression e can be explicitly converted to a type T
  //   [...] if the declaration "T t(e);" is well-formed, [...].
  tcr = TryStaticImplicitCast(Self, SrcExpr, DestType, CCK, OpRange, msg,
                              Kind, ListInitialization);
  if (SrcExpr.isInvalid())
    return TC_Failed;
  if (tcr != TC_NotApplicable)
    return tcr;

  // C++ 5.2.9p6: May apply the reverse of any standard conversion, except
  // lvalue-to-rvalue, array-to-pointer, function-to-pointer, and boolean
  // conversions, subject to further restrictions.
  // Also, C++ 5.2.9p1 forbids casting away constness, which makes reversal
  // of qualification conversions impossible.
  // In the CStyle case, the earlier attempt to const_cast should have taken
  // care of reverse qualification conversions.

  QualType SrcType = Self.Context.getCanonicalType(SrcExpr.get()->getType());

  // C++0x 5.2.9p9: A value of a scoped enumeration type can be explicitly
  // converted to an integral type. [...] A value of a scoped enumeration type
  // can also be explicitly converted to a floating-point type [...].
  if (const EnumType *Enum = SrcType->getAs<EnumType>()) {
    if (Enum->getDecl()->isScoped()) {
      if (DestType->isBooleanType()) {
        Kind = CK_IntegralToBoolean;
        return TC_Success;
      } else if (DestType->isIntegralType(Self.Context)) {
        Kind = CK_IntegralCast;
        return TC_Success;
      } else if (DestType->isRealFloatingType()) {
        Kind = CK_IntegralToFloating;
        return TC_Success;
      }
    }
  }

  // Reverse integral promotion/conversion. All such conversions are themselves
  // again integral promotions or conversions and are thus already handled by
  // p2 (TryDirectInitialization above).
  // (Note: any data loss warnings should be suppressed.)
  // The exception is the reverse of enum->integer, i.e. integer->enum (and
  // enum->enum). See also C++ 5.2.9p7.
  // The same goes for reverse floating point promotion/conversion and
  // floating-integral conversions. Again, only floating->enum is relevant.
  if (DestType->isEnumeralType()) {
    if (SrcType->isIntegralOrEnumerationType()) {
      Kind = CK_IntegralCast;
      return TC_Success;
    } else if (SrcType->isRealFloatingType())   {
      Kind = CK_FloatingToIntegral;
      return TC_Success;
    }
  }

  // Reverse pointer upcast. C++ 4.10p3 specifies pointer upcast.
  // C++ 5.2.9p8 additionally disallows a cast path through virtual inheritance.
  tcr = TryStaticPointerDowncast(Self, SrcType, DestType, CStyle, OpRange, msg,
                                 Kind, BasePath);
  if (tcr != TC_NotApplicable)
    return tcr;

  // Reverse member pointer conversion. C++ 4.11 specifies member pointer
  // conversion. C++ 5.2.9p9 has additional information.
  // DR54's access restrictions apply here also.
  tcr = TryStaticMemberPointerUpcast(Self, SrcExpr, SrcType, DestType, CStyle,
                                     OpRange, msg, Kind, BasePath);
  if (tcr != TC_NotApplicable)
    return tcr;

  // Reverse pointer conversion to void*. C++ 4.10.p2 specifies conversion to
  // void*. C++ 5.2.9p10 specifies additional restrictions, which really is
  // just the usual constness stuff.
  if (const PointerType *SrcPointer = SrcType->getAs<PointerType>()) {
    QualType SrcPointee = SrcPointer->getPointeeType();
    if (SrcPointee->isVoidType()) {
      if (const PointerType *DestPointer = DestType->getAs<PointerType>()) {
        QualType DestPointee = DestPointer->getPointeeType();
        if (DestPointee->isIncompleteOrObjectType()) {
          // This is definitely the intended conversion, but it might fail due
          // to a qualifier violation. Note that we permit Objective-C lifetime
          // and GC qualifier mismatches here.
          if (!CStyle) {
            Qualifiers DestPointeeQuals = DestPointee.getQualifiers();
            Qualifiers SrcPointeeQuals = SrcPointee.getQualifiers();
            DestPointeeQuals.removeObjCGCAttr();
            DestPointeeQuals.removeObjCLifetime();
            SrcPointeeQuals.removeObjCGCAttr();
            SrcPointeeQuals.removeObjCLifetime();
            if (DestPointeeQuals != SrcPointeeQuals &&
                !DestPointeeQuals.compatiblyIncludes(SrcPointeeQuals)) {
              msg = diag::err_bad_cxx_cast_qualifiers_away;
              return TC_Failed;
            }
          }
          Kind = IsAddressSpaceConversion(SrcType, DestType)
                     ? CK_AddressSpaceConversion
                     : CK_BitCast;
          return TC_Success;
        }

        // Microsoft permits static_cast from 'pointer-to-void' to
        // 'pointer-to-function'.
        if (!CStyle && Self.getLangOpts().MSVCCompat &&
            DestPointee->isFunctionType()) {
          Self.Diag(OpRange.getBegin(), diag::ext_ms_cast_fn_obj) << OpRange;
          Kind = CK_BitCast;
          return TC_Success;
        }
      }
      else if (DestType->isObjCObjectPointerType()) {
        // allow both c-style cast and static_cast of objective-c pointers as
        // they are pervasive.
        Kind = CK_CPointerToObjCPointerCast;
        return TC_Success;
      }
      else if (CStyle && DestType->isBlockPointerType()) {
        // allow c-style cast of void * to block pointers.
        Kind = CK_AnyPointerToBlockPointerCast;
        return TC_Success;
      }
    }
  }
  // Allow arbitrary objective-c pointer conversion with static casts.
  if (SrcType->isObjCObjectPointerType() &&
      DestType->isObjCObjectPointerType()) {
    Kind = CK_BitCast;
    return TC_Success;
  }
  // Allow ns-pointer to cf-pointer conversion in either direction
  // with static casts.
  if (!CStyle &&
      Self.CheckTollFreeBridgeStaticCast(DestType, SrcExpr.get(), Kind))
    return TC_Success;

  // See if it looks like the user is trying to convert between
  // related record types, and select a better diagnostic if so.
  if (auto SrcPointer = SrcType->getAs<PointerType>())
    if (auto DestPointer = DestType->getAs<PointerType>())
      if (SrcPointer->getPointeeType()->getAs<RecordType>() &&
          DestPointer->getPointeeType()->getAs<RecordType>())
       msg = diag::err_bad_cxx_cast_unrelated_class;

  // We tried everything. Everything! Nothing works! :-(
  return TC_NotApplicable;
}

/// Tests whether a conversion according to N2844 is valid.
TryCastResult TryLValueToRValueCast(Sema &Self, Expr *SrcExpr,
                                    QualType DestType, bool CStyle,
                                    CastKind &Kind, CXXCastPath &BasePath,
                                    unsigned &msg) {
  // C++11 [expr.static.cast]p3:
  //   A glvalue of type "cv1 T1" can be cast to type "rvalue reference to
  //   cv2 T2" if "cv2 T2" is reference-compatible with "cv1 T1".
  const RValueReferenceType *R = DestType->getAs<RValueReferenceType>();
  if (!R)
    return TC_NotApplicable;

  if (!SrcExpr->isGLValue())
    return TC_NotApplicable;

  // Because we try the reference downcast before this function, from now on
  // this is the only cast possibility, so we issue an error if we fail now.
  // FIXME: Should allow casting away constness if CStyle.
  bool DerivedToBase;
  bool ObjCConversion;
  bool ObjCLifetimeConversion;
  QualType FromType = SrcExpr->getType();
  QualType ToType = R->getPointeeType();
  if (CStyle) {
    FromType = FromType.getUnqualifiedType();
    ToType = ToType.getUnqualifiedType();
  }

  Sema::ReferenceCompareResult RefResult = Self.CompareReferenceRelationship(
      SrcExpr->getBeginLoc(), ToType, FromType, DerivedToBase, ObjCConversion,
      ObjCLifetimeConversion);
  if (RefResult != Sema::Ref_Compatible) {
    if (CStyle || RefResult == Sema::Ref_Incompatible)
      return TC_NotApplicable;
    // Diagnose types which are reference-related but not compatible here since
    // we can provide better diagnostics. In these cases forwarding to
    // [expr.static.cast]p4 should never result in a well-formed cast.
    msg = SrcExpr->isLValue() ? diag::err_bad_lvalue_to_rvalue_cast
                              : diag::err_bad_rvalue_to_rvalue_cast;
    return TC_Failed;
  }

  if (DerivedToBase) {
    Kind = CK_DerivedToBase;
    CXXBasePaths Paths(/*FindAmbiguities=*/true, /*RecordPaths=*/true,
                       /*DetectVirtual=*/true);
    if (!Self.IsDerivedFrom(SrcExpr->getBeginLoc(), SrcExpr->getType(),
                            R->getPointeeType(), Paths))
      return TC_NotApplicable;

    Self.BuildBasePathArray(Paths, BasePath);
  } else
    Kind = CK_NoOp;

  return TC_Success;
}

/// Tests whether a conversion according to C++ 5.2.9p5 is valid.
TryCastResult
TryStaticReferenceDowncast(Sema &Self, Expr *SrcExpr, QualType DestType,
                           bool CStyle, SourceRange OpRange,
                           unsigned &msg, CastKind &Kind,
                           CXXCastPath &BasePath) {
  // C++ 5.2.9p5: An lvalue of type "cv1 B", where B is a class type, can be
  //   cast to type "reference to cv2 D", where D is a class derived from B,
  //   if a valid standard conversion from "pointer to D" to "pointer to B"
  //   exists, cv2 >= cv1, and B is not a virtual base class of D.
  // In addition, DR54 clarifies that the base must be accessible in the
  // current context. Although the wording of DR54 only applies to the pointer
  // variant of this rule, the intent is clearly for it to apply to the this
  // conversion as well.

  const ReferenceType *DestReference = DestType->getAs<ReferenceType>();
  if (!DestReference) {
    return TC_NotApplicable;
  }
  bool RValueRef = DestReference->isRValueReferenceType();
  if (!RValueRef && !SrcExpr->isLValue()) {
    // We know the left side is an lvalue reference, so we can suggest a reason.
    msg = diag::err_bad_cxx_cast_rvalue;
    return TC_NotApplicable;
  }

  QualType DestPointee = DestReference->getPointeeType();

  if (IsBadCheriReferenceCast(DestReference, SrcExpr, Self.getASTContext())) {
    msg = diag::err_bad_cxx_reference_cast_capability_qualifier;
    return TC_Failed;
  }

  // FIXME: If the source is a prvalue, we should issue a warning (because the
  // cast always has undefined behavior), and for AST consistency, we should
  // materialize a temporary.
  return TryStaticDowncast(Self,
                           Self.Context.getCanonicalType(SrcExpr->getType()),
                           Self.Context.getCanonicalType(DestPointee), CStyle,
                           OpRange, SrcExpr->getType(), DestType, msg, Kind,
                           BasePath);
}

/// Tests whether a conversion according to C++ 5.2.9p8 is valid.
TryCastResult
TryStaticPointerDowncast(Sema &Self, QualType SrcType, QualType DestType,
                         bool CStyle, SourceRange OpRange,
                         unsigned &msg, CastKind &Kind,
                         CXXCastPath &BasePath) {
  // C++ 5.2.9p8: An rvalue of type "pointer to cv1 B", where B is a class
  //   type, can be converted to an rvalue of type "pointer to cv2 D", where D
  //   is a class derived from B, if a valid standard conversion from "pointer
  //   to D" to "pointer to B" exists, cv2 >= cv1, and B is not a virtual base
  //   class of D.
  // In addition, DR54 clarifies that the base must be accessible in the
  // current context.

  const PointerType *DestPointer = DestType->getAs<PointerType>();
  if (!DestPointer) {
    return TC_NotApplicable;
  }

  const PointerType *SrcPointer = SrcType->getAs<PointerType>();
  if (!SrcPointer) {
    msg = diag::err_bad_static_cast_pointer_nonpointer;
    return TC_NotApplicable;
  }

  return TryStaticDowncast(Self,
                   Self.Context.getCanonicalType(SrcPointer->getPointeeType()),
                  Self.Context.getCanonicalType(DestPointer->getPointeeType()),
                           CStyle, OpRange, SrcType, DestType, msg, Kind,
                           BasePath);
}

/// TryStaticDowncast - Common functionality of TryStaticReferenceDowncast and
/// TryStaticPointerDowncast. Tests whether a static downcast from SrcType to
/// DestType is possible and allowed.
TryCastResult
TryStaticDowncast(Sema &Self, CanQualType SrcType, CanQualType DestType,
                  bool CStyle, SourceRange OpRange, QualType OrigSrcType,
                  QualType OrigDestType, unsigned &msg,
                  CastKind &Kind, CXXCastPath &BasePath) {
  // We can only work with complete types. But don't complain if it doesn't work
  if (!Self.isCompleteType(OpRange.getBegin(), SrcType) ||
      !Self.isCompleteType(OpRange.getBegin(), DestType))
    return TC_NotApplicable;

  // Downcast can only happen in class hierarchies, so we need classes.
  if (!DestType->getAs<RecordType>() || !SrcType->getAs<RecordType>()) {
    return TC_NotApplicable;
  }

  CXXBasePaths Paths(/*FindAmbiguities=*/true, /*RecordPaths=*/true,
                     /*DetectVirtual=*/true);
  if (!Self.IsDerivedFrom(OpRange.getBegin(), DestType, SrcType, Paths)) {
    return TC_NotApplicable;
  }

  // Target type does derive from source type. Now we're serious. If an error
  // appears now, it's not ignored.
  // This may not be entirely in line with the standard. Take for example:
  // struct A {};
  // struct B : virtual A {
  //   B(A&);
  // };
  //
  // void f()
  // {
  //   (void)static_cast<const B&>(*((A*)0));
  // }
  // As far as the standard is concerned, p5 does not apply (A is virtual), so
  // p2 should be used instead - "const B& t(*((A*)0));" is perfectly valid.
  // However, both GCC and Comeau reject this example, and accepting it would
  // mean more complex code if we're to preserve the nice error message.
  // FIXME: Being 100% compliant here would be nice to have.

  // Must preserve cv, as always, unless we're in C-style mode.
  if (!CStyle && !DestType.isAtLeastAsQualifiedAs(SrcType)) {
    msg = diag::err_bad_cxx_cast_qualifiers_away;
    return TC_Failed;
  }

  if (Paths.isAmbiguous(SrcType.getUnqualifiedType())) {
    // This code is analoguous to that in CheckDerivedToBaseConversion, except
    // that it builds the paths in reverse order.
    // To sum up: record all paths to the base and build a nice string from
    // them. Use it to spice up the error message.
    if (!Paths.isRecordingPaths()) {
      Paths.clear();
      Paths.setRecordingPaths(true);
      Self.IsDerivedFrom(OpRange.getBegin(), DestType, SrcType, Paths);
    }
    std::string PathDisplayStr;
    std::set<unsigned> DisplayedPaths;
    for (clang::CXXBasePath &Path : Paths) {
      if (DisplayedPaths.insert(Path.back().SubobjectNumber).second) {
        // We haven't displayed a path to this particular base
        // class subobject yet.
        PathDisplayStr += "\n    ";
        for (CXXBasePathElement &PE : llvm::reverse(Path))
          PathDisplayStr += PE.Base->getType().getAsString() + " -> ";
        PathDisplayStr += QualType(DestType).getAsString();
      }
    }

    Self.Diag(OpRange.getBegin(), diag::err_ambiguous_base_to_derived_cast)
      << QualType(SrcType).getUnqualifiedType()
      << QualType(DestType).getUnqualifiedType()
      << PathDisplayStr << OpRange;
    msg = 0;
    return TC_Failed;
  }

  if (Paths.getDetectedVirtual() != nullptr) {
    QualType VirtualBase(Paths.getDetectedVirtual(), 0);
    Self.Diag(OpRange.getBegin(), diag::err_static_downcast_via_virtual)
      << OrigSrcType << OrigDestType << VirtualBase << OpRange;
    msg = 0;
    return TC_Failed;
  }

  if (!CStyle) {
    switch (Self.CheckBaseClassAccess(OpRange.getBegin(),
                                      SrcType, DestType,
                                      Paths.front(),
                                diag::err_downcast_from_inaccessible_base)) {
    case Sema::AR_accessible:
    case Sema::AR_delayed:     // be optimistic
    case Sema::AR_dependent:   // be optimistic
      break;

    case Sema::AR_inaccessible:
      msg = 0;
      return TC_Failed;
    }
  }

  Self.BuildBasePathArray(Paths, BasePath);
  Kind = CK_BaseToDerived;
  return TC_Success;
}

/// TryStaticMemberPointerUpcast - Tests whether a conversion according to
/// C++ 5.2.9p9 is valid:
///
///   An rvalue of type "pointer to member of D of type cv1 T" can be
///   converted to an rvalue of type "pointer to member of B of type cv2 T",
///   where B is a base class of D [...].
///
TryCastResult
TryStaticMemberPointerUpcast(Sema &Self, ExprResult &SrcExpr, QualType SrcType,
                             QualType DestType, bool CStyle,
                             SourceRange OpRange,
                             unsigned &msg, CastKind &Kind,
                             CXXCastPath &BasePath) {
  const MemberPointerType *DestMemPtr = DestType->getAs<MemberPointerType>();
  if (!DestMemPtr)
    return TC_NotApplicable;

  bool WasOverloadedFunction = false;
  DeclAccessPair FoundOverload;
  if (SrcExpr.get()->getType() == Self.Context.OverloadTy) {
    if (FunctionDecl *Fn
          = Self.ResolveAddressOfOverloadedFunction(SrcExpr.get(), DestType, false,
                                                    FoundOverload)) {
      CXXMethodDecl *M = cast<CXXMethodDecl>(Fn);
      SrcType = Self.Context.getMemberPointerType(Fn->getType(),
                      Self.Context.getTypeDeclType(M->getParent()).getTypePtr());
      WasOverloadedFunction = true;
    }
  }

  const MemberPointerType *SrcMemPtr = SrcType->getAs<MemberPointerType>();
  if (!SrcMemPtr) {
    msg = diag::err_bad_static_cast_member_pointer_nonmp;
    return TC_NotApplicable;
  }

  // Lock down the inheritance model right now in MS ABI, whether or not the
  // pointee types are the same.
  if (Self.Context.getTargetInfo().getCXXABI().isMicrosoft()) {
    (void)Self.isCompleteType(OpRange.getBegin(), SrcType);
    (void)Self.isCompleteType(OpRange.getBegin(), DestType);
  }

  // T == T, modulo cv
  if (!Self.Context.hasSameUnqualifiedType(SrcMemPtr->getPointeeType(),
                                           DestMemPtr->getPointeeType()))
    return TC_NotApplicable;

  // B base of D
  QualType SrcClass(SrcMemPtr->getClass(), 0);
  QualType DestClass(DestMemPtr->getClass(), 0);
  CXXBasePaths Paths(/*FindAmbiguities=*/true, /*RecordPaths=*/true,
                  /*DetectVirtual=*/true);
  if (!Self.IsDerivedFrom(OpRange.getBegin(), SrcClass, DestClass, Paths))
    return TC_NotApplicable;

  // B is a base of D. But is it an allowed base? If not, it's a hard error.
  if (Paths.isAmbiguous(Self.Context.getCanonicalType(DestClass))) {
    Paths.clear();
    Paths.setRecordingPaths(true);
    bool StillOkay =
        Self.IsDerivedFrom(OpRange.getBegin(), SrcClass, DestClass, Paths);
    assert(StillOkay);
    (void)StillOkay;
    std::string PathDisplayStr = Self.getAmbiguousPathsDisplayString(Paths);
    Self.Diag(OpRange.getBegin(), diag::err_ambiguous_memptr_conv)
      << 1 << SrcClass << DestClass << PathDisplayStr << OpRange;
    msg = 0;
    return TC_Failed;
  }

  if (const RecordType *VBase = Paths.getDetectedVirtual()) {
    Self.Diag(OpRange.getBegin(), diag::err_memptr_conv_via_virtual)
      << SrcClass << DestClass << QualType(VBase, 0) << OpRange;
    msg = 0;
    return TC_Failed;
  }

  if (!CStyle) {
    switch (Self.CheckBaseClassAccess(OpRange.getBegin(),
                                      DestClass, SrcClass,
                                      Paths.front(),
                                      diag::err_upcast_to_inaccessible_base)) {
    case Sema::AR_accessible:
    case Sema::AR_delayed:
    case Sema::AR_dependent:
      // Optimistically assume that the delayed and dependent cases
      // will work out.
      break;

    case Sema::AR_inaccessible:
      msg = 0;
      return TC_Failed;
    }
  }

  if (WasOverloadedFunction) {
    // Resolve the address of the overloaded function again, this time
    // allowing complaints if something goes wrong.
    FunctionDecl *Fn = Self.ResolveAddressOfOverloadedFunction(SrcExpr.get(),
                                                               DestType,
                                                               true,
                                                               FoundOverload);
    if (!Fn) {
      msg = 0;
      return TC_Failed;
    }

    SrcExpr = Self.FixOverloadedFunctionReference(SrcExpr, FoundOverload, Fn);
    if (!SrcExpr.isUsable()) {
      msg = 0;
      return TC_Failed;
    }
  }

  Self.BuildBasePathArray(Paths, BasePath);
  Kind = CK_DerivedToBaseMemberPointer;
  return TC_Success;
}

/// TryStaticImplicitCast - Tests whether a conversion according to C++ 5.2.9p2
/// is valid:
///
///   An expression e can be explicitly converted to a type T using a
///   @c static_cast if the declaration "T t(e);" is well-formed [...].
TryCastResult
TryStaticImplicitCast(Sema &Self, ExprResult &SrcExpr, QualType DestType,
                      Sema::CheckedConversionKind CCK,
                      SourceRange OpRange, unsigned &msg,
                      CastKind &Kind, bool ListInitialization) {
  if (DestType->isRecordType()) {
    if (Self.RequireCompleteType(OpRange.getBegin(), DestType,
                                 diag::err_bad_dynamic_cast_incomplete) ||
        Self.RequireNonAbstractType(OpRange.getBegin(), DestType,
                                    diag::err_allocation_of_abstract_type)) {
      msg = 0;
      return TC_Failed;
    }
  }

  InitializedEntity Entity = InitializedEntity::InitializeTemporary(DestType);
  InitializationKind InitKind
    = (CCK == Sema::CCK_CStyleCast)
        ? InitializationKind::CreateCStyleCast(OpRange.getBegin(), OpRange,
                                               ListInitialization)
    : (CCK == Sema::CCK_FunctionalCast)
        ? InitializationKind::CreateFunctionalCast(OpRange, ListInitialization)
    : InitializationKind::CreateCast(OpRange);
  Expr *SrcExprRaw = SrcExpr.get();
  // FIXME: Per DR242, we should check for an implicit conversion sequence
  // or for a constructor that could be invoked by direct-initialization
  // here, not for an initialization sequence.
  InitializationSequence InitSeq(Self, Entity, InitKind, SrcExprRaw);

  // At this point of CheckStaticCast, if the destination is a reference,
  // or the expression is an overload expression this has to work.
  // There is no other way that works.
  // On the other hand, if we're checking a C-style cast, we've still got
  // the reinterpret_cast way.
  bool CStyle
    = (CCK == Sema::CCK_CStyleCast || CCK == Sema::CCK_FunctionalCast);
  if (InitSeq.Failed() && (CStyle || !DestType->isReferenceType()))
    return TC_NotApplicable;

  ExprResult Result = InitSeq.Perform(Self, Entity, InitKind, SrcExprRaw);
  if (Result.isInvalid()) {
    msg = 0;
    return TC_Failed;
  }

  if (InitSeq.isConstructorInitialization())
    Kind = CK_ConstructorConversion;
  else
    Kind = CK_NoOp;

  SrcExpr = Result;
  return TC_Success;
}

/// TryConstCast - See if a const_cast from source to destination is allowed,
/// and perform it if it is.
static TryCastResult TryConstCast(Sema &Self, ExprResult &SrcExpr,
                                  QualType DestType, bool CStyle,
                                  unsigned &msg) {
  DestType = Self.Context.getCanonicalType(DestType);
  QualType SrcType = SrcExpr.get()->getType();
  bool NeedToMaterializeTemporary = false;

  if (const ReferenceType *DestTypeTmp =DestType->getAs<ReferenceType>()) {
    // C++11 5.2.11p4:
    //   if a pointer to T1 can be explicitly converted to the type "pointer to
    //   T2" using a const_cast, then the following conversions can also be
    //   made:
    //    -- an lvalue of type T1 can be explicitly converted to an lvalue of
    //       type T2 using the cast const_cast<T2&>;
    //    -- a glvalue of type T1 can be explicitly converted to an xvalue of
    //       type T2 using the cast const_cast<T2&&>; and
    //    -- if T1 is a class type, a prvalue of type T1 can be explicitly
    //       converted to an xvalue of type T2 using the cast const_cast<T2&&>.

    if (isa<LValueReferenceType>(DestTypeTmp) && !SrcExpr.get()->isLValue()) {
      // Cannot const_cast non-lvalue to lvalue reference type. But if this
      // is C-style, static_cast might find a way, so we simply suggest a
      // message and tell the parent to keep searching.
      msg = diag::err_bad_cxx_cast_rvalue;
      return TC_NotApplicable;
    }

    if (isa<RValueReferenceType>(DestTypeTmp) && SrcExpr.get()->isRValue()) {
      if (!SrcType->isRecordType()) {
        // Cannot const_cast non-class prvalue to rvalue reference type. But if
        // this is C-style, static_cast can do this.
        msg = diag::err_bad_cxx_cast_rvalue;
        return TC_NotApplicable;
      }

      // Materialize the class prvalue so that the const_cast can bind a
      // reference to it.
      NeedToMaterializeTemporary = true;
    }

    // It's not completely clear under the standard whether we can
    // const_cast bit-field gl-values.  Doing so would not be
    // intrinsically complicated, but for now, we say no for
    // consistency with other compilers and await the word of the
    // committee.
    if (SrcExpr.get()->refersToBitField()) {
      msg = diag::err_bad_cxx_cast_bitfield;
      return TC_NotApplicable;
    }

    if (IsBadCheriReferenceCast(DestTypeTmp, SrcExpr.get(),
                                Self.getASTContext())) {
      msg = diag::err_bad_cxx_reference_cast_capability_qualifier;
      return TC_NotApplicable;
    }

    DestType = Self.Context.getPointerType(DestTypeTmp->getPointeeType());
    SrcType = Self.Context.getPointerType(SrcType);
  }

  // C++ 5.2.11p5: For a const_cast involving pointers to data members [...]
  //   the rules for const_cast are the same as those used for pointers.

  if (!DestType->isPointerType() &&
      !DestType->isMemberPointerType() &&
      !DestType->isObjCObjectPointerType()) {
    // Cannot cast to non-pointer, non-reference type. Note that, if DestType
    // was a reference type, we converted it to a pointer above.
    // The status of rvalue references isn't entirely clear, but it looks like
    // conversion to them is simply invalid.
    // C++ 5.2.11p3: For two pointer types [...]
    if (!CStyle)
      msg = diag::err_bad_const_cast_dest;
    return TC_NotApplicable;
  }
  if (DestType->isFunctionPointerType() ||
      DestType->isMemberFunctionPointerType()) {
    // Cannot cast direct function pointers.
    // C++ 5.2.11p2: [...] where T is any object type or the void type [...]
    // T is the ultimate pointee of source and target type.
    if (!CStyle)
      msg = diag::err_bad_const_cast_dest;
    return TC_NotApplicable;
  }

  // C++ [expr.const.cast]p3:
  //   "For two similar types T1 and T2, [...]"
  //
  // We only allow a const_cast to change cvr-qualifiers, not other kinds of
  // type qualifiers. (Likewise, we ignore other changes when determining
  // whether a cast casts away constness.)
  if (!Self.Context.hasCvrSimilarType(SrcType, DestType))
    return TC_NotApplicable;

  if (NeedToMaterializeTemporary)
    // This is a const_cast from a class prvalue to an rvalue reference type.
    // Materialize a temporary to store the result of the conversion.
    SrcExpr = Self.CreateMaterializeTemporaryExpr(SrcExpr.get()->getType(),
                                                  SrcExpr.get(),
                                                  /*IsLValueReference*/ false);

  return TC_Success;
}

// Checks for undefined behavior in reinterpret_cast.
// The cases that is checked for is:
// *reinterpret_cast<T*>(&a)
// reinterpret_cast<T&>(a)
// where accessing 'a' as type 'T' will result in undefined behavior.
void Sema::CheckCompatibleReinterpretCast(QualType SrcType, QualType DestType,
                                          bool IsDereference,
                                          SourceRange Range) {
  unsigned DiagID = IsDereference ?
                        diag::warn_pointer_indirection_from_incompatible_type :
                        diag::warn_undefined_reinterpret_cast;

  if (Diags.isIgnored(DiagID, Range.getBegin()))
    return;

  QualType SrcTy, DestTy;
  if (IsDereference) {
    if (!SrcType->getAs<PointerType>() || !DestType->getAs<PointerType>()) {
      return;
    }
    SrcTy = SrcType->getPointeeType();
    DestTy = DestType->getPointeeType();
  } else {
    if (!DestType->getAs<ReferenceType>()) {
      return;
    }
    SrcTy = SrcType;
    DestTy = DestType->getPointeeType();
  }

  // Cast is compatible if the types are the same.
  if (Context.hasSameUnqualifiedType(DestTy, SrcTy)) {
    return;
  }
  // or one of the types is a char or void type
  if (DestTy->isAnyCharacterType() || DestTy->isVoidType() ||
      SrcTy->isAnyCharacterType() || SrcTy->isVoidType()) {
    return;
  }
  // or one of the types is a tag type.
  if (SrcTy->getAs<TagType>() || DestTy->getAs<TagType>()) {
    return;
  }

  // FIXME: Scoped enums?
  if ((SrcTy->isUnsignedIntegerType() && DestTy->isSignedIntegerType()) ||
      (SrcTy->isSignedIntegerType() && DestTy->isUnsignedIntegerType())) {
    if (Context.getTypeSize(DestTy) == Context.getTypeSize(SrcTy)) {
      return;
    }
  }

  Diag(Range.getBegin(), DiagID) << SrcType << DestType << Range;
}

static void DiagnoseCHERICallback(Sema &Self, SourceLocation Loc,
                                  QualType SrcType, QualType DestType) {
  bool SrcIsCallback = false;
  bool DestIsCallback = false;
  if (auto SrcPointer = dyn_cast<PointerType>(SrcType))
    if (auto SrcFnPTy = SrcPointer->getPointeeType()->getAs<FunctionType>())
      if (SrcFnPTy->getCallConv() == CC_CHERICCallback)
        SrcIsCallback = true;
  if (auto DestPointer = dyn_cast<PointerType>(DestType))
    if (auto DestFnPTy = DestPointer->getPointeeType()->getAs<FunctionType>())
      if (DestFnPTy->getCallConv() == CC_CHERICCallback)
        DestIsCallback = true;
  if (SrcIsCallback != DestIsCallback)
    Self.Diag(Loc, diag::err_cheri_invalid_callback_cast);
}

static void DiagnoseCHERIPtr(Sema &Self, Expr *SrcExpr, QualType DestType,
                              CastKind &Kind, SourceRange &Range) {
  if (Kind != CK_BitCast)
    return;
  
  const PointerType *SrcPtr = SrcExpr->getType()->getAs<PointerType>();
  const PointerType *DestPtr = DestType->getAs<PointerType>();
  if (SrcPtr && DestPtr && !SrcPtr->isCHERICapability() && !DestPtr->isCHERICapability()) {
    QualType SrcPointee = SrcPtr->getPointeeType();
    QualType DestPointee = DestPtr->getPointeeType();
    
    // casts from char * and void * are implicitly allowed
    if (SrcPointee->isCharType() || SrcPointee->isVoidType())
      return;

    if (!SrcPointee->isCHERICapabilityType(Self.Context, true) &&
        DestPointee->isCHERICapabilityType(Self.Context, true)) {
      CharUnits SrcAlign = Self.Context.getTypeAlignInChars(SrcPointee);
      CharUnits DestAlign = Self.Context.getTypeAlignInChars(DestPointee);

      if (SrcAlign >= DestAlign)
        return;

      Self.Diag(Range.getBegin(), diag::err_cheri_ptr_align)
        << SrcExpr->getType() << DestType
        << static_cast<unsigned>(SrcAlign.getQuantity())
        << static_cast<unsigned>(DestAlign.getQuantity())
        << Range << SrcExpr->getSourceRange();
      Self.Diag(Range.getEnd(), diag::note_cheri_ptr_align_fixit);
    }
  }
}

static CastKind DiagnoseCapabilityToIntCast(Sema &Self, SourceRange OpRange,
                                            const Expr *SrcExpr,
                                            QualType DestType) {
  if (Self.Context.getLangOpts().getCheriCapConversion() ==
      LangOptions::CapConv_Ignore)
    return CK_NoOp;

  QualType SrcType = SrcExpr->getRealReferenceType(Self.Context);
  if (SrcType->isDependentType() || DestType->isDependentType())
    return CK_NoOp; // can't diagnose this yet
  // If the source is not a capability or a __uintcap_t we can ignore it
  if (!SrcType->isCHERICapabilityType(Self.Context, /*IncludeIntCap=*/false)) {
    return CK_NoOp; // Not casting from a capability
  }
  if (DestType->isCHERICapabilityType(Self.Context, /*IncludeIntCap=*/true)) {
    return CK_NoOp; // cast from capabilty to capability is fine
  }
  if (DestType->isVoidType()) {
    return CK_NoOp; // casting to void to silence unused variable warnings is fine
  }
  if (SrcType->isNullPtrType()) {
    return CK_NoOp;
  }

  // auto C = DestType.getCanonicalType();
  // llvm::errs() << "Checking if " << DestType.getAsString() << " is a memoryAddressType -- canonical=" << C.getAsString() << "\n";
  // DestType.dump("is memaddr?");
  // C.dump("canonical");
  // llvm::errs() << "Is integral: " << DestType->isIntegralOrEnumerationType() << " C " << C->isIntegralOrEnumerationType() << "\n";
  
  // check if it is a valid type for memory addresses such as vaddr_t
  // FIXME: is there something simpler that I can do?
  // bool IsMemAddressType = DestType->getDecl()->hasAttr<MemoryAddressAttr>();
  bool IsMemAddressType = DestType->hasAttr(attr::MemoryAddress);
  if (DestType->isPointerType() || DestType->isReferenceType()) {
    Self.Diag(OpRange.getBegin(), diag::warn_capability_pointer_cast)
        << SrcType << DestType << OpRange
        << FixItHint::CreateReplacement(OpRange, "__cheri_fromcap " +
                                                     DestType.getAsString());
    return CK_CHERICapabilityToPointer;

  } else if (!IsMemAddressType) {
    Self.Diag(OpRange.getBegin(), diag::warn_capability_integer_cast)
        << SrcType << DestType << OpRange;
  }
  return CK_NoOp;
}

static void DiagnoseCastOfObjCSEL(Sema &Self, const ExprResult &SrcExpr,
                                  QualType DestType) {
  QualType SrcType = SrcExpr.get()->getType();
  if (Self.Context.hasSameType(SrcType, DestType))
    return;
  if (const PointerType *SrcPtrTy = SrcType->getAs<PointerType>())
    if (SrcPtrTy->isObjCSelType()) {
      QualType DT = DestType;
      if (isa<PointerType>(DestType))
        DT = DestType->getPointeeType();
      if (!DT.getUnqualifiedType()->isVoidType())
        Self.Diag(SrcExpr.get()->getExprLoc(),
                  diag::warn_cast_pointer_from_sel)
        << SrcType << DestType << SrcExpr.get()->getSourceRange();
    }
}

/// Diagnose casts that change the calling convention of a pointer to a function
/// defined in the current TU.
static void DiagnoseCallingConvCast(Sema &Self, const ExprResult &SrcExpr,
                                    QualType DstType, SourceRange OpRange) {
  // Check if this cast would change the calling convention of a function
  // pointer type.
  QualType SrcType = SrcExpr.get()->getType();
  if (Self.Context.hasSameType(SrcType, DstType) ||
      !SrcType->isFunctionPointerType() || !DstType->isFunctionPointerType())
    return;
  const auto *SrcFTy =
      SrcType->castAs<PointerType>()->getPointeeType()->castAs<FunctionType>();
  const auto *DstFTy =
      DstType->castAs<PointerType>()->getPointeeType()->castAs<FunctionType>();
  CallingConv SrcCC = SrcFTy->getCallConv();
  CallingConv DstCC = DstFTy->getCallConv();
  if (SrcCC == DstCC)
    return;

  // We have a calling convention cast. Check if the source is a pointer to a
  // known, specific function that has already been defined.
  Expr *Src = SrcExpr.get()->IgnoreParenImpCasts();
  if (auto *UO = dyn_cast<UnaryOperator>(Src))
    if (UO->getOpcode() == UO_AddrOf)
      Src = UO->getSubExpr()->IgnoreParenImpCasts();
  auto *DRE = dyn_cast<DeclRefExpr>(Src);
  if (!DRE)
    return;
  auto *FD = dyn_cast<FunctionDecl>(DRE->getDecl());
  if (!FD)
    return;

  // Only warn if we are casting from the default convention to a non-default
  // convention. This can happen when the programmer forgot to apply the calling
  // convention to the function declaration and then inserted this cast to
  // satisfy the type system.
  CallingConv DefaultCC = Self.getASTContext().getDefaultCallingConvention(
      FD->isVariadic(), FD->isCXXInstanceMember());
  if (DstCC == DefaultCC || SrcCC != DefaultCC)
    return;

  // Diagnose this cast, as it is probably bad.
  StringRef SrcCCName = FunctionType::getNameForCallConv(SrcCC);
  StringRef DstCCName = FunctionType::getNameForCallConv(DstCC);
  Self.Diag(OpRange.getBegin(), diag::warn_cast_calling_conv)
      << SrcCCName << DstCCName << OpRange;

  // The checks above are cheaper than checking if the diagnostic is enabled.
  // However, it's worth checking if the warning is enabled before we construct
  // a fixit.
  if (Self.Diags.isIgnored(diag::warn_cast_calling_conv, OpRange.getBegin()))
    return;

  // Try to suggest a fixit to change the calling convention of the function
  // whose address was taken. Try to use the latest macro for the convention.
  // For example, users probably want to write "WINAPI" instead of "__stdcall"
  // to match the Windows header declarations.
  SourceLocation NameLoc = FD->getFirstDecl()->getNameInfo().getLoc();
  Preprocessor &PP = Self.getPreprocessor();
  SmallVector<TokenValue, 6> AttrTokens;
  SmallString<64> CCAttrText;
  llvm::raw_svector_ostream OS(CCAttrText);
  if (Self.getLangOpts().MicrosoftExt) {
    // __stdcall or __vectorcall
    OS << "__" << DstCCName;
    IdentifierInfo *II = PP.getIdentifierInfo(OS.str());
    AttrTokens.push_back(II->isKeyword(Self.getLangOpts())
                             ? TokenValue(II->getTokenID())
                             : TokenValue(II));
  } else {
    // __attribute__((stdcall)) or __attribute__((vectorcall))
    OS << "__attribute__((" << DstCCName << "))";
    AttrTokens.push_back(tok::kw___attribute);
    AttrTokens.push_back(tok::l_paren);
    AttrTokens.push_back(tok::l_paren);
    IdentifierInfo *II = PP.getIdentifierInfo(DstCCName);
    AttrTokens.push_back(II->isKeyword(Self.getLangOpts())
                             ? TokenValue(II->getTokenID())
                             : TokenValue(II));
    AttrTokens.push_back(tok::r_paren);
    AttrTokens.push_back(tok::r_paren);
  }
  StringRef AttrSpelling = PP.getLastMacroWithSpelling(NameLoc, AttrTokens);
  if (!AttrSpelling.empty())
    CCAttrText = AttrSpelling;
  OS << ' ';
  Self.Diag(NameLoc, diag::note_change_calling_conv_fixit)
      << FD << DstCCName << FixItHint::CreateInsertion(NameLoc, CCAttrText);
}

static void checkIntToPointerCast(bool CStyle, SourceLocation Loc,
                                  const Expr *SrcExpr, QualType DestType,
                                  Sema &Self) {
  QualType SrcType = SrcExpr->getType();
  ASTContext &Ctx = Self.getASTContext();

  if (DestType->isCHERICapabilityType(Ctx, true) &&
      !SrcType->isCHERICapabilityType(Ctx, true) &&
      !SrcExpr->isIntegerConstantExpr(Ctx)) {
    Self.Diag(Loc, diag::warn_capability_no_provenance) << DestType;
    Self.Diag(Loc, diag::note_insert_intptr_fixit);
  }

  // Not warning on reinterpret_cast, boolean, constant expressions, etc
  // are not explicit design choices, but consistent with GCC's behavior.
  // Feel free to modify them if you've reason/evidence for an alternative.
  if (CStyle && SrcType->isIntegralType(Self.Context) &&
      !SrcType->isBooleanType() && !SrcType->isEnumeralType() &&
      !SrcExpr->isIntegerConstantExpr(Self.Context) &&
      Ctx.getIntRange(DestType) > Ctx.getIntRange(SrcType)) {
    // Separate between casts to void* and non-void* pointers.
    // Some APIs use (abuse) void* for something like a user context,
    // and often that value is an integer even if it isn't a pointer itself.
    // Having a separate warning flag allows users to control the warning
    // for their workflow.
    unsigned Diag = DestType->isVoidPointerType() ?
                      diag::warn_int_to_void_pointer_cast
                    : diag::warn_int_to_pointer_cast;
    Self.Diag(Loc, Diag) << SrcType << DestType;
  }
}

static bool fixOverloadedReinterpretCastExpr(Sema &Self, QualType DestType,
                                             ExprResult &Result) {
  // We can only fix an overloaded reinterpret_cast if
  // - it is a template with explicit arguments that resolves to an lvalue
  //   unambiguously, or
  // - it is the only function in an overload set that may have its address
  //   taken.

  Expr *E = Result.get();
  // TODO: what if this fails because of DiagnoseUseOfDecl or something
  // like it?
  if (Self.ResolveAndFixSingleFunctionTemplateSpecialization(
          Result,
          Expr::getValueKindForType(DestType) == VK_RValue // Convert Fun to Ptr
          ) &&
      Result.isUsable())
    return true;

  // No guarantees that ResolveAndFixSingleFunctionTemplateSpecialization
  // preserves Result.
  Result = E;
  if (!Self.resolveAndFixAddressOfOnlyViableOverloadCandidate(
          Result, /*DoFunctionPointerConversion=*/true))
    return false;
  return Result.isUsable();
}

static TryCastResult TryReinterpretCast(Sema &Self, ExprResult &SrcExpr,
                                        QualType DestType, bool CStyle,
                                        SourceRange OpRange,
                                        unsigned &msg,
                                        CastKind &Kind) {
  bool IsLValueCast = false;

  DestType = Self.Context.getCanonicalType(DestType);
  QualType SrcType = SrcExpr.get()->getType();

  // Is the source an overloaded name? (i.e. &foo)
  // If so, reinterpret_cast generally can not help us here (13.4, p1, bullet 5)
  if (SrcType == Self.Context.OverloadTy) {
    ExprResult FixedExpr = SrcExpr;
    if (!fixOverloadedReinterpretCastExpr(Self, DestType, FixedExpr))
      return TC_NotApplicable;

    assert(FixedExpr.isUsable() && "Invalid result fixing overloaded expr");
    SrcExpr = FixedExpr;
    SrcType = SrcExpr.get()->getType();
  }

  if (const ReferenceType *DestTypeTmp = DestType->getAs<ReferenceType>()) {
    if (!SrcExpr.get()->isGLValue()) {
      // Cannot cast non-glvalue to (lvalue or rvalue) reference type. See the
      // similar comment in const_cast.
      msg = diag::err_bad_cxx_cast_rvalue;
      return TC_NotApplicable;
    }

    if (!CStyle) {
      Self.CheckCompatibleReinterpretCast(SrcType, DestType,
                                          /*isDereference=*/false, OpRange);
    }

    // C++ 5.2.10p10: [...] a reference cast reinterpret_cast<T&>(x) has the
    //   same effect as the conversion *reinterpret_cast<T*>(&x) with the
    //   built-in & and * operators.

    const char *inappropriate = nullptr;
    switch (SrcExpr.get()->getObjectKind()) {
    case OK_Ordinary:
      break;
    case OK_BitField:
      msg = diag::err_bad_cxx_cast_bitfield;
      return TC_NotApplicable;
      // FIXME: Use a specific diagnostic for the rest of these cases.
    case OK_VectorComponent: inappropriate = "vector element";      break;
    case OK_ObjCProperty:    inappropriate = "property expression"; break;
    case OK_ObjCSubscript:   inappropriate = "container subscripting expression";
                             break;
    }
    if (inappropriate) {
      Self.Diag(OpRange.getBegin(), diag::err_bad_reinterpret_cast_reference)
          << inappropriate << DestType
          << OpRange << SrcExpr.get()->getSourceRange();
      msg = 0; SrcExpr = ExprError();
      return TC_NotApplicable;
    }

    if (IsBadCheriReferenceCast(DestTypeTmp, SrcExpr.get(), Self.getASTContext())) {
      msg = diag::err_bad_cxx_reference_cast_capability_qualifier;
      return TC_Failed;
    }

    // This code does this transformation for the checked types.
    DestType = Self.Context.getPointerType(DestTypeTmp->getPointeeType());
    SrcType = Self.Context.getPointerType(SrcType);

    IsLValueCast = true;
  }

  // Canonicalize source for comparison.
  SrcType = Self.Context.getCanonicalType(SrcType);

  const MemberPointerType *DestMemPtr = DestType->getAs<MemberPointerType>(),
                          *SrcMemPtr = SrcType->getAs<MemberPointerType>();
  if (DestMemPtr && SrcMemPtr) {
    // C++ 5.2.10p9: An rvalue of type "pointer to member of X of type T1"
    //   can be explicitly converted to an rvalue of type "pointer to member
    //   of Y of type T2" if T1 and T2 are both function types or both object
    //   types.
    if (DestMemPtr->isMemberFunctionPointer() !=
        SrcMemPtr->isMemberFunctionPointer())
      return TC_NotApplicable;

    if (Self.Context.getTargetInfo().getCXXABI().isMicrosoft()) {
      // We need to determine the inheritance model that the class will use if
      // haven't yet.
      (void)Self.isCompleteType(OpRange.getBegin(), SrcType);
      (void)Self.isCompleteType(OpRange.getBegin(), DestType);
    }

    // Don't allow casting between member pointers of different sizes.
    if (Self.Context.getTypeSize(DestMemPtr) !=
        Self.Context.getTypeSize(SrcMemPtr)) {
      msg = diag::err_bad_cxx_cast_member_pointer_size;
      return TC_Failed;
    }

    // C++ 5.2.10p2: The reinterpret_cast operator shall not cast away
    //   constness.
    // A reinterpret_cast followed by a const_cast can, though, so in C-style,
    // we accept it.
    if (auto CACK =
            CastsAwayConstness(Self, SrcType, DestType, /*CheckCVR=*/!CStyle,
                               /*CheckObjCLifetime=*/CStyle))
      return getCastAwayConstnessCastKind(CACK, msg);

    // A valid member pointer cast.
    assert(!IsLValueCast);
    Kind = CK_ReinterpretMemberPointer;
    return TC_Success;
  }

  // See below for the enumeral issue.
  if (SrcType->isNullPtrType() && DestType->isIntegralType(Self.Context)) {
    // C++0x 5.2.10p4: A pointer can be explicitly converted to any integral
    //   type large enough to hold it. A value of std::nullptr_t can be
    //   converted to an integral type; the conversion has the same meaning
    //   and validity as a conversion of (void*)0 to the integral type.
    bool SrcIsCap = SrcType->isCHERICapabilityType(Self.Context);
    // In purecap ABI casting to uint64_t is fine as we want the pointer range
    uint64_t Size = SrcIsCap
        ? Self.Context.getTargetInfo().getPointerRangeForCHERICapability()
        : Self.Context.getTypeSize(SrcType);
    if (Size > Self.Context.getTypeSize(DestType)) {
      msg = SrcIsCap ? diag::err_bad_cap_reinterpret_cast_small_int :
                       diag::err_bad_reinterpret_cast_small_int;
      return TC_Failed;
    }
    Kind = SrcIsCap && !DestType->isIntCapType() ? CK_CHERICapabilityToAddress
                                                 : CK_PointerToIntegral;
    return TC_Success;
  }

  // Allow reinterpret_casts between vectors of the same size and
  // between vectors and integers of the same size.
  bool destIsVector = DestType->isVectorType();
  bool srcIsVector = SrcType->isVectorType();
  if (srcIsVector || destIsVector) {
    // The non-vector type, if any, must have integral type.  This is
    // the same rule that C vector casts use; note, however, that enum
    // types are not integral in C++.
    if ((!destIsVector && !DestType->isIntegralType(Self.Context)) ||
        (!srcIsVector && !SrcType->isIntegralType(Self.Context)))
      return TC_NotApplicable;

    // The size we want to consider is eltCount * eltSize.
    // That's exactly what the lax-conversion rules will check.
    if (Self.areLaxCompatibleVectorTypes(SrcType, DestType)) {
      Kind = CK_BitCast;
      return TC_Success;
    }

    // Otherwise, pick a reasonable diagnostic.
    if (!destIsVector)
      msg = diag::err_bad_cxx_cast_vector_to_scalar_different_size;
    else if (!srcIsVector)
      msg = diag::err_bad_cxx_cast_scalar_to_vector_different_size;
    else
      msg = diag::err_bad_cxx_cast_vector_to_vector_different_size;

    return TC_Failed;
  }

  if (SrcType == DestType) {
    // C++ 5.2.10p2 has a note that mentions that, subject to all other
    // restrictions, a cast to the same type is allowed so long as it does not
    // cast away constness. In C++98, the intent was not entirely clear here,
    // since all other paragraphs explicitly forbid casts to the same type.
    // C++11 clarifies this case with p2.
    //
    // The only allowed types are: integral, enumeration, pointer, or
    // pointer-to-member types.  We also won't restrict Obj-C pointers either.
    Kind = CK_NoOp;
    TryCastResult Result = TC_NotApplicable;
    if (SrcType->isIntegralOrEnumerationType() ||
        SrcType->isAnyPointerType() ||
        SrcType->isMemberPointerType() ||
        SrcType->isBlockPointerType()) {
      Result = TC_Success;
    }
    return Result;
  }

  bool destIsPtr = DestType->isAnyPointerType() ||
                   DestType->isBlockPointerType();
  bool srcIsPtr = SrcType->isAnyPointerType() ||
                  SrcType->isBlockPointerType();
  if (!destIsPtr && !srcIsPtr) {
    // Except for std::nullptr_t->integer and lvalue->reference, which are
    // handled above, at least one of the two arguments must be a pointer.
    return TC_NotApplicable;
  }

  if (DestType->isIntegralType(Self.Context)) {
    assert(srcIsPtr && "One type must be a pointer");
    // C++ 5.2.10p4: A pointer can be explicitly converted to any integral
    //   type large enough to hold it; except in Microsoft mode, where the
    //   integral type size doesn't matter (except we don't allow bool).
    bool MicrosoftException = Self.getLangOpts().MicrosoftExt &&
                              !DestType->isBooleanType();
    bool SrcIsCap = SrcType->isCHERICapabilityType(Self.Context);
    // In purecap ABI casting to uint64_t is fine as we want the pointer range
    uint64_t Size = SrcIsCap
        ? Self.Context.getTargetInfo().getPointerRangeForCHERICapability()
        : Self.Context.getTypeSize(SrcType);
    if ((Size > Self.Context.getTypeSize(DestType)) && !MicrosoftException) {
      msg = SrcIsCap ? diag::err_bad_cap_reinterpret_cast_small_int :
                       diag::err_bad_reinterpret_cast_small_int;
      return TC_Failed;
    }
    Kind = SrcIsCap && !DestType->isIntCapType() ? CK_CHERICapabilityToAddress
                                                 : CK_PointerToIntegral;
    return TC_Success;
  }

  if (SrcType->isIntegralOrEnumerationType()) {
    assert(destIsPtr && "One type must be a pointer");
    checkIntToPointerCast(CStyle, OpRange.getBegin(), SrcExpr.get(), DestType,
                          Self);
    // C++ 5.2.10p5: A value of integral or enumeration type can be explicitly
    //   converted to a pointer.
    // C++ 5.2.10p9: [Note: ...a null pointer constant of integral type is not
    //   necessarily converted to a null pointer value.]
    Kind = CK_IntegralToPointer;
    return TC_Success;
  }

  if (!destIsPtr || !srcIsPtr) {
    // With the valid non-pointer conversions out of the way, we can be even
    // more stringent.
    return TC_NotApplicable;
  }

  // Cannot convert between block pointers and Objective-C object pointers.
  if ((SrcType->isBlockPointerType() && DestType->isObjCObjectPointerType()) ||
      (DestType->isBlockPointerType() && SrcType->isObjCObjectPointerType()))
    return TC_NotApplicable;

  // C++ 5.2.10p2: The reinterpret_cast operator shall not cast away constness.
  // The C-style cast operator can.
  TryCastResult SuccessResult = TC_Success;
  if (auto CACK =
          CastsAwayConstness(Self, SrcType, DestType, /*CheckCVR=*/!CStyle,
                             /*CheckObjCLifetime=*/CStyle))
    SuccessResult = getCastAwayConstnessCastKind(CACK, msg);

  if (IsAddressSpaceConversion(SrcType, DestType)) {
    Kind = CK_AddressSpaceConversion;
    assert(SrcType->isPointerType() && DestType->isPointerType());
    if (!CStyle &&
        !DestType->getPointeeType().getQualifiers().isAddressSpaceSupersetOf(
            SrcType->getPointeeType().getQualifiers())) {
      SuccessResult = TC_Failed;
    }
  } else if (IsLValueCast) {
    Kind = CK_LValueBitCast;
  } else if (DestType->isObjCObjectPointerType()) {
    Kind = Self.PrepareCastToObjCObjectPointer(SrcExpr);
  } else if (DestType->isBlockPointerType()) {
    if (!SrcType->isBlockPointerType()) {
      Kind = CK_AnyPointerToBlockPointerCast;
    } else {
      Kind = CK_BitCast;
    }
  } else {
    Kind = CK_BitCast;
  }

  // Any pointer can be cast to an Objective-C pointer type with a C-style
  // cast.
  if (CStyle && DestType->isObjCObjectPointerType()) {
    return SuccessResult;
  }
  if (CStyle)
    DiagnoseCastOfObjCSEL(Self, SrcExpr, DestType);

  DiagnoseCallingConvCast(Self, SrcExpr, DestType, OpRange);

  // Not casting away constness, so the only remaining check is for compatible
  // pointer categories.

  if (SrcType->isFunctionPointerType()) {
    if (DestType->isFunctionPointerType()) {
      // C++ 5.2.10p6: A pointer to a function can be explicitly converted to
      // a pointer to a function of a different type.
      return SuccessResult;
    }

    // C++0x 5.2.10p8: Converting a pointer to a function into a pointer to
    //   an object type or vice versa is conditionally-supported.
    // Compilers support it in C++03 too, though, because it's necessary for
    // casting the return value of dlsym() and GetProcAddress().
    // FIXME: Conditionally-supported behavior should be configurable in the
    // TargetInfo or similar.
    Self.Diag(OpRange.getBegin(),
              Self.getLangOpts().CPlusPlus11 ?
                diag::warn_cxx98_compat_cast_fn_obj : diag::ext_cast_fn_obj)
      << OpRange;
    return SuccessResult;
  }

  if (DestType->isFunctionPointerType()) {
    // See above.
    Self.Diag(OpRange.getBegin(),
              Self.getLangOpts().CPlusPlus11 ?
                diag::warn_cxx98_compat_cast_fn_obj : diag::ext_cast_fn_obj)
      << OpRange;
    return SuccessResult;
  }

  // C++ 5.2.10p7: A pointer to an object can be explicitly converted to
  //   a pointer to an object of different type.
  // Void pointers are not specified, but supported by every compiler out there.
  // So we finish by allowing everything that remains - it's got to be two
  // object pointers.
  return SuccessResult;
}

static TryCastResult TryAddressSpaceCast(Sema &Self, ExprResult &SrcExpr,
                                         QualType DestType, bool CStyle,
                                         unsigned &msg) {
  if (!Self.getLangOpts().OpenCL)
    // FIXME: As compiler doesn't have any information about overlapping addr
    // spaces at the moment we have to be permissive here.
    return TC_NotApplicable;
  // Even though the logic below is general enough and can be applied to
  // non-OpenCL mode too, we fast-path above because no other languages
  // define overlapping address spaces currently.
  auto SrcType = SrcExpr.get()->getType();
  auto SrcPtrType = SrcType->getAs<PointerType>();
  if (!SrcPtrType)
    return TC_NotApplicable;
  auto DestPtrType = DestType->getAs<PointerType>();
  if (!DestPtrType)
    return TC_NotApplicable;
  auto SrcPointeeType = SrcPtrType->getPointeeType();
  auto DestPointeeType = DestPtrType->getPointeeType();
  if (SrcPointeeType.getAddressSpace() == DestPointeeType.getAddressSpace())
    return TC_NotApplicable;
  if (!DestPtrType->isAddressSpaceOverlapping(*SrcPtrType)) {
    msg = diag::err_bad_cxx_cast_addr_space_mismatch;
    return TC_Failed;
  }
  auto SrcPointeeTypeWithoutAS =
      Self.Context.removeAddrSpaceQualType(SrcPointeeType.getCanonicalType());
  auto DestPointeeTypeWithoutAS =
      Self.Context.removeAddrSpaceQualType(DestPointeeType.getCanonicalType());
  return Self.Context.hasSameType(SrcPointeeTypeWithoutAS,
                                  DestPointeeTypeWithoutAS)
             ? TC_Success
             : TC_NotApplicable;
}

void CastOperation::checkAddressSpaceCast(QualType SrcType, QualType DestType) {
  // In OpenCL only conversions between pointers to objects in overlapping
  // addr spaces are allowed. v2.0 s6.5.5 - Generic addr space overlaps
  // with any named one, except for constant.
  if (Self.getLangOpts().OpenCL) {
    auto SrcPtrType = SrcType->getAs<PointerType>();
    if (!SrcPtrType)
      return;
    auto DestPtrType = DestType->getAs<PointerType>();
    if (!DestPtrType)
      return;
    if (!DestPtrType->isAddressSpaceOverlapping(*SrcPtrType)) {
      Self.Diag(OpRange.getBegin(),
                diag::err_typecheck_incompatible_address_space)
          << SrcType << DestType << Sema::AA_Casting
          << SrcExpr.get()->getSourceRange();
      SrcExpr = ExprError();
    }
  }
}

void CastOperation::CheckCXXCStyleCast(bool FunctionalStyle,
                                       bool ListInitialization) {
  assert(Self.getLangOpts().CPlusPlus);

  // Handle placeholders.
  if (isPlaceholder()) {
    // C-style casts can resolve __unknown_any types.
    if (claimPlaceholder(BuiltinType::UnknownAny)) {
      SrcExpr = Self.checkUnknownAnyCast(DestRange, DestType,
                                         SrcExpr.get(), Kind,
                                         ValueKind, BasePath);
      return;
    }

    checkNonOverloadPlaceholders();
    if (SrcExpr.isInvalid())
      return;
  }

  // C++ 5.2.9p4: Any expression can be explicitly converted to type "cv void".
  // This test is outside everything else because it's the only case where
  // a non-lvalue-reference target type does not lead to decay.
  if (DestType->isVoidType()) {
    Kind = CK_ToVoid;

    if (claimPlaceholder(BuiltinType::Overload)) {
      Self.ResolveAndFixSingleFunctionTemplateSpecialization(
                  SrcExpr, /* Decay Function to ptr */ false,
                  /* Complain */ true, DestRange, DestType,
                  diag::err_bad_cstyle_cast_overload);
      if (SrcExpr.isInvalid())
        return;
    }

    SrcExpr = Self.IgnoredValueConversions(SrcExpr.get());
    return;
  }

  // If the type is dependent, we won't do any other semantic analysis now.
  if (DestType->isDependentType() || SrcExpr.get()->isTypeDependent() ||
      SrcExpr.get()->isValueDependent()) {
    assert(Kind == CK_Dependent);
    return;
  }

  if (ValueKind == VK_RValue && !DestType->isRecordType() &&
      !isPlaceholder(BuiltinType::Overload)) {
    SrcExpr = Self.DefaultFunctionArrayLvalueConversion(SrcExpr.get());
    if (SrcExpr.isInvalid())
      return;
  }

  // AltiVec vector initialization with a single literal.
  if (const VectorType *vecTy = DestType->getAs<VectorType>())
    if (vecTy->getVectorKind() == VectorType::AltiVecVector
        && (SrcExpr.get()->getType()->isIntegerType()
            || SrcExpr.get()->getType()->isFloatingType())) {
      Kind = CK_VectorSplat;
      SrcExpr = Self.prepareVectorSplat(DestType, SrcExpr.get());
      return;
    }

  // C++ [expr.cast]p5: The conversions performed by
  //   - a const_cast,
  //   - a static_cast,
  //   - a static_cast followed by a const_cast,
  //   - a reinterpret_cast, or
  //   - a reinterpret_cast followed by a const_cast,
  //   can be performed using the cast notation of explicit type conversion.
  //   [...] If a conversion can be interpreted in more than one of the ways
  //   listed above, the interpretation that appears first in the list is used,
  //   even if a cast resulting from that interpretation is ill-formed.
  // In plain language, this means trying a const_cast ...
  // Note that for address space we check compatibility after const_cast.
  unsigned msg = diag::err_bad_cxx_cast_generic;
  TryCastResult tcr = TryConstCast(Self, SrcExpr, DestType,
                                   /*CStyle*/ true, msg);
  if (SrcExpr.isInvalid())
    return;
  if (isValidCast(tcr))
    Kind = CK_NoOp;

  Sema::CheckedConversionKind CCK =
      FunctionalStyle ? Sema::CCK_FunctionalCast : Sema::CCK_CStyleCast;
  if (tcr == TC_NotApplicable) {
    tcr = TryAddressSpaceCast(Self, SrcExpr, DestType, /*CStyle*/ true, msg);
    if (SrcExpr.isInvalid())
      return;
    if (tcr == TC_NotApplicable) {
      // ... or if that is not possible, a static_cast, ignoring const, ...
      tcr = TryStaticCast(Self, SrcExpr, DestType, CCK, OpRange, msg, Kind,
                          BasePath, ListInitialization);
      if (SrcExpr.isInvalid())
        return;

      if (tcr == TC_NotApplicable) {
        // ... and finally a reinterpret_cast, ignoring const.
        tcr = TryReinterpretCast(Self, SrcExpr, DestType, /*CStyle*/ true,
                                 OpRange, msg, Kind);
        if (SrcExpr.isInvalid())
          return;
      }
    }
  }

  if (Self.getLangOpts().allowsNonTrivialObjCLifetimeQualifiers() &&
      isValidCast(tcr))
    checkObjCConversion(CCK);

  if (tcr != TC_Success && msg != 0) {
    if (SrcExpr.get()->getType() == Self.Context.OverloadTy) {
      DeclAccessPair Found;
      FunctionDecl *Fn = Self.ResolveAddressOfOverloadedFunction(SrcExpr.get(),
                                DestType,
                                /*Complain*/ true,
                                Found);
      if (Fn) {
        // If DestType is a function type (not to be confused with the function
        // pointer type), it will be possible to resolve the function address,
        // but the type cast should be considered as failure.
        OverloadExpr *OE = OverloadExpr::find(SrcExpr.get()).Expression;
        Self.Diag(OpRange.getBegin(), diag::err_bad_cstyle_cast_overload)
          << OE->getName() << DestType << OpRange
          << OE->getQualifierLoc().getSourceRange();
        Self.NoteAllOverloadCandidates(SrcExpr.get());
      }
    } else {
      diagnoseBadCast(Self, msg, (FunctionalStyle ? CT_Functional : CT_CStyle),
                      OpRange, SrcExpr.get(), DestType, ListInitialization);
    }
  }

  if (isValidCast(tcr)) {
    if (Kind == CK_BitCast)
      checkCastAlign();
  } else {
    SrcExpr = ExprError();
  }
}

/// DiagnoseBadFunctionCast - Warn whenever a function call is cast to a
///  non-matching type. Such as enum function call to int, int call to
/// pointer; etc. Cast to 'void' is an exception.
static void DiagnoseBadFunctionCast(Sema &Self, const ExprResult &SrcExpr,
                                  QualType DestType) {
  if (Self.Diags.isIgnored(diag::warn_bad_function_cast,
                           SrcExpr.get()->getExprLoc()))
    return;

  if (!isa<CallExpr>(SrcExpr.get()))
    return;

  QualType SrcType = SrcExpr.get()->getType();
  if (DestType.getUnqualifiedType()->isVoidType())
    return;
  if ((SrcType->isAnyPointerType() || SrcType->isBlockPointerType())
      && (DestType->isAnyPointerType() || DestType->isBlockPointerType()))
    return;
  if (SrcType->isIntegerType() && DestType->isIntegerType() &&
      (SrcType->isBooleanType() == DestType->isBooleanType()) &&
      (SrcType->isEnumeralType() == DestType->isEnumeralType()))
    return;
  if (SrcType->isRealFloatingType() && DestType->isRealFloatingType())
    return;
  if (SrcType->isEnumeralType() && DestType->isEnumeralType())
    return;
  if (SrcType->isComplexType() && DestType->isComplexType())
    return;
  if (SrcType->isComplexIntegerType() && DestType->isComplexIntegerType())
    return;

  Self.Diag(SrcExpr.get()->getExprLoc(),
            diag::warn_bad_function_cast)
            << SrcType << DestType << SrcExpr.get()->getSourceRange();
}

/// Check the semantics of a C-style cast operation, in C.
void CastOperation::CheckCStyleCast() {
  assert(!Self.getLangOpts().CPlusPlus);

  // C-style casts can resolve __unknown_any types.
  if (claimPlaceholder(BuiltinType::UnknownAny)) {
    SrcExpr = Self.checkUnknownAnyCast(DestRange, DestType,
                                       SrcExpr.get(), Kind,
                                       ValueKind, BasePath);
    return;
  }

  // C99 6.5.4p2: the cast type needs to be void or scalar and the expression
  // type needs to be scalar.
  if (DestType->isVoidType()) {
    // We don't necessarily do lvalue-to-rvalue conversions on this.
    SrcExpr = Self.IgnoredValueConversions(SrcExpr.get());
    if (SrcExpr.isInvalid())
      return;

    // Cast to void allows any expr type.
    Kind = CK_ToVoid;
    return;
  }

  // Overloads are allowed with C extensions, so we need to support them.
  if (SrcExpr.get()->getType() == Self.Context.OverloadTy) {
    DeclAccessPair DAP;
    if (FunctionDecl *FD = Self.ResolveAddressOfOverloadedFunction(
            SrcExpr.get(), DestType, /*Complain=*/true, DAP))
      SrcExpr = Self.FixOverloadedFunctionReference(SrcExpr.get(), DAP, FD);
    else
      return;
    assert(SrcExpr.isUsable());
  }
  SrcExpr = Self.DefaultFunctionArrayLvalueConversion(SrcExpr.get());
  if (SrcExpr.isInvalid())
    return;
  QualType SrcType = SrcExpr.get()->getType();

  assert(!SrcType->isPlaceholderType());

  checkAddressSpaceCast(SrcType, DestType);
  if (SrcExpr.isInvalid())
    return;

  if (Self.RequireCompleteType(OpRange.getBegin(), DestType,
                               diag::err_typecheck_cast_to_incomplete)) {
    SrcExpr = ExprError();
    return;
  }

  if (!DestType->isScalarType() && !DestType->isVectorType()) {
    const RecordType *DestRecordTy = DestType->getAs<RecordType>();

    if (DestRecordTy && Self.Context.hasSameUnqualifiedType(DestType, SrcType)){
      // GCC struct/union extension: allow cast to self.
      Self.Diag(OpRange.getBegin(), diag::ext_typecheck_cast_nonscalar)
        << DestType << SrcExpr.get()->getSourceRange();
      Kind = CK_NoOp;
      return;
    }

    // GCC's cast to union extension.
    if (DestRecordTy && DestRecordTy->getDecl()->isUnion()) {
      RecordDecl *RD = DestRecordTy->getDecl();
      if (CastExpr::getTargetFieldForToUnionCast(RD, SrcType)) {
        Self.Diag(OpRange.getBegin(), diag::ext_typecheck_cast_to_union)
          << SrcExpr.get()->getSourceRange();
        Kind = CK_ToUnion;
        return;
      } else {
        Self.Diag(OpRange.getBegin(), diag::err_typecheck_cast_to_union_no_type)
          << SrcType << SrcExpr.get()->getSourceRange();
        SrcExpr = ExprError();
        return;
      }
    }

    // OpenCL v2.0 s6.13.10 - Allow casts from '0' to event_t type.
    if (Self.getLangOpts().OpenCL && DestType->isEventT()) {
      Expr::EvalResult Result;
      if (SrcExpr.get()->EvaluateAsInt(Result, Self.Context)) {
        llvm::APSInt CastInt = Result.Val.getInt();
        if (0 == CastInt) {
          Kind = CK_ZeroToOCLOpaqueType;
          return;
        }
        Self.Diag(OpRange.getBegin(),
                  diag::err_opencl_cast_non_zero_to_event_t)
                  << CastInt.toString(10) << SrcExpr.get()->getSourceRange();
        SrcExpr = ExprError();
        return;
      }
    }

    // Reject any other conversions to non-scalar types.
    Self.Diag(OpRange.getBegin(), diag::err_typecheck_cond_expect_scalar)
      << DestType << SrcExpr.get()->getSourceRange();
    SrcExpr = ExprError();
    return;
  }

  // The type we're casting to is known to be a scalar or vector.

  // Require the operand to be a scalar or vector.
  if (!SrcType->isScalarType() && !SrcType->isVectorType()) {
    Self.Diag(SrcExpr.get()->getExprLoc(),
              diag::err_typecheck_expect_scalar_operand)
      << SrcType << SrcExpr.get()->getSourceRange();
    SrcExpr = ExprError();
    return;
  }

  if (DestType->isExtVectorType()) {
    SrcExpr = Self.CheckExtVectorCast(OpRange, DestType, SrcExpr.get(), Kind);
    return;
  }

  if (const VectorType *DestVecTy = DestType->getAs<VectorType>()) {
    if (DestVecTy->getVectorKind() == VectorType::AltiVecVector &&
          (SrcType->isIntegerType() || SrcType->isFloatingType())) {
      Kind = CK_VectorSplat;
      SrcExpr = Self.prepareVectorSplat(DestType, SrcExpr.get());
    } else if (Self.CheckVectorCast(OpRange, DestType, SrcType, Kind)) {
      SrcExpr = ExprError();
    }
    return;
  }

  if (SrcType->isVectorType()) {
    if (Self.CheckVectorCast(OpRange, SrcType, DestType, Kind))
      SrcExpr = ExprError();
    return;
  }

  // The source and target types are both scalars, i.e.
  //   - arithmetic types (fundamental, enum, and complex)
  //   - all kinds of pointers
  // Note that member pointers were filtered out with C++, above.

  if (isa<ObjCSelectorExpr>(SrcExpr.get())) {
    Self.Diag(SrcExpr.get()->getExprLoc(), diag::err_cast_selector_expr);
    SrcExpr = ExprError();
    return;
  }

  // If either type is a pointer, the other type has to be either an
  // integer or a pointer.
  if (!DestType->isArithmeticType()) {
    if (!SrcType->isIntegralType(Self.Context) && SrcType->isArithmeticType()) {
      Self.Diag(SrcExpr.get()->getExprLoc(),
                diag::err_cast_pointer_from_non_pointer_int)
        << SrcType << SrcExpr.get()->getSourceRange();
      SrcExpr = ExprError();
      return;
    }
    checkIntToPointerCast(/* CStyle */ true, OpRange.getBegin(), SrcExpr.get(),
                          DestType, Self);
  } else if (!SrcType->isArithmeticType()) {
    if (!DestType->isIntegralType(Self.Context) &&
        DestType->isArithmeticType()) {
      Self.Diag(SrcExpr.get()->getBeginLoc(),
                diag::err_cast_pointer_to_non_pointer_int)
          << DestType << SrcExpr.get()->getSourceRange();
      SrcExpr = ExprError();
      return;
    }
  }

  if (Self.getLangOpts().OpenCL &&
      !Self.getOpenCLOptions().isEnabled("cl_khr_fp16")) {
    if (DestType->isHalfType()) {
      Self.Diag(SrcExpr.get()->getBeginLoc(), diag::err_opencl_cast_to_half)
          << DestType << SrcExpr.get()->getSourceRange();
      SrcExpr = ExprError();
      return;
    }
  }

  // ARC imposes extra restrictions on casts.
  if (Self.getLangOpts().allowsNonTrivialObjCLifetimeQualifiers()) {
    checkObjCConversion(Sema::CCK_CStyleCast);
    if (SrcExpr.isInvalid())
      return;

    const PointerType *CastPtr = DestType->getAs<PointerType>();
    if (Self.getLangOpts().ObjCAutoRefCount && CastPtr) {
      if (const PointerType *ExprPtr = SrcType->getAs<PointerType>()) {
        Qualifiers CastQuals = CastPtr->getPointeeType().getQualifiers();
        Qualifiers ExprQuals = ExprPtr->getPointeeType().getQualifiers();
        if (CastPtr->getPointeeType()->isObjCLifetimeType() &&
            ExprPtr->getPointeeType()->isObjCLifetimeType() &&
            !CastQuals.compatiblyIncludesObjCLifetime(ExprQuals)) {
          Self.Diag(SrcExpr.get()->getBeginLoc(),
                    diag::err_typecheck_incompatible_ownership)
              << SrcType << DestType << Sema::AA_Casting
              << SrcExpr.get()->getSourceRange();
          return;
        }
      }
    }
    else if (!Self.CheckObjCARCUnavailableWeakConversion(DestType, SrcType)) {
      Self.Diag(SrcExpr.get()->getBeginLoc(),
                diag::err_arc_convesion_of_weak_unavailable)
          << 1 << SrcType << DestType << SrcExpr.get()->getSourceRange();
      SrcExpr = ExprError();
      return;
    }
  }

  DiagnoseCHERICallback(Self, SrcExpr.get()->getBeginLoc(), SrcType, DestType);
  DiagnoseCastOfObjCSEL(Self, SrcExpr, DestType);
  DiagnoseCallingConvCast(Self, SrcExpr, DestType, OpRange);
  DiagnoseBadFunctionCast(Self, SrcExpr, DestType);
  Kind = Self.PrepareScalarCast(SrcExpr, DestType);
  DiagnoseCHERIPtr(Self, SrcExpr.get(), DestType, Kind, OpRange);

  if (SrcExpr.isInvalid())
    return;

  if (Kind == CK_BitCast)
    checkCastAlign();
}

/// DiagnoseCastQual - Warn whenever casts discards a qualifiers, be it either
/// const, volatile or both.
static void DiagnoseCastQual(Sema &Self, const ExprResult &SrcExpr,
                             QualType DestType) {
  if (SrcExpr.isInvalid())
    return;

  QualType SrcType = SrcExpr.get()->getType();
  if (!((SrcType->isAnyPointerType() && DestType->isAnyPointerType()) ||
        DestType->isLValueReferenceType()))
    return;

  QualType TheOffendingSrcType, TheOffendingDestType;
  Qualifiers CastAwayQualifiers;
  if (CastsAwayConstness(Self, SrcType, DestType, true, false,
                         &TheOffendingSrcType, &TheOffendingDestType,
                         &CastAwayQualifiers) !=
      CastAwayConstnessKind::CACK_Similar)
    return;

  // FIXME: 'restrict' is not properly handled here.
  int qualifiers = -1;
  if (CastAwayQualifiers.hasConst() && CastAwayQualifiers.hasVolatile()) {
    qualifiers = 0;
  } else if (CastAwayQualifiers.hasConst()) {
    qualifiers = 1;
  } else if (CastAwayQualifiers.hasVolatile()) {
    qualifiers = 2;
  }
  // This is a variant of int **x; const int **y = (const int **)x;
  if (qualifiers == -1)
    Self.Diag(SrcExpr.get()->getBeginLoc(), diag::warn_cast_qual2)
        << SrcType << DestType;
  else
    Self.Diag(SrcExpr.get()->getBeginLoc(), diag::warn_cast_qual)
        << TheOffendingSrcType << TheOffendingDestType << qualifiers;
}

ExprResult Sema::BuildCStyleCastExpr(SourceLocation LPLoc,
                                     TypeSourceInfo *CastTypeInfo,
                                     SourceLocation RPLoc,
                                     Expr *CastExpr) {
  CastOperation Op(*this, CastTypeInfo->getType(), CastExpr);
  Op.DestRange = CastTypeInfo->getTypeLoc().getSourceRange();
  Op.OpRange = SourceRange(LPLoc, CastExpr->getEndLoc());

  if (getLangOpts().CPlusPlus) {
    Op.CheckCXXCStyleCast(/*FunctionalStyle=*/ false,
                          isa<InitListExpr>(CastExpr));
  } else {
    Op.CheckCStyleCast();
  }

  if (Op.SrcExpr.isInvalid())
    return ExprError();

  // -Wcast-qual
  DiagnoseCastQual(Op.Self, Op.SrcExpr, Op.DestType);

  return Op.complete(CStyleCastExpr::Create(Context, Op.ResultType,
                              Op.ValueKind, Op.Kind, Op.SrcExpr.get(),
                              &Op.BasePath, CastTypeInfo, LPLoc, RPLoc));
}

ExprResult Sema::BuildCXXFunctionalCastExpr(TypeSourceInfo *CastTypeInfo,
                                            QualType Type,
                                            SourceLocation LPLoc,
                                            Expr *CastExpr,
                                            SourceLocation RPLoc) {
  assert(LPLoc.isValid() && "List-initialization shouldn't get here.");
  CastOperation Op(*this, Type, CastExpr);
  Op.DestRange = CastTypeInfo->getTypeLoc().getSourceRange();
  Op.OpRange = SourceRange(Op.DestRange.getBegin(), CastExpr->getEndLoc());

  Op.CheckCXXCStyleCast(/*FunctionalStyle=*/true, /*ListInit=*/false);
  if (Op.SrcExpr.isInvalid())
    return ExprError();

  auto *SubExpr = Op.SrcExpr.get();
  if (auto *BindExpr = dyn_cast<CXXBindTemporaryExpr>(SubExpr))
    SubExpr = BindExpr->getSubExpr();
  if (auto *ConstructExpr = dyn_cast<CXXConstructExpr>(SubExpr))
    ConstructExpr->setParenOrBraceRange(SourceRange(LPLoc, RPLoc));

  return Op.complete(CXXFunctionalCastExpr::Create(Context, Op.ResultType,
                         Op.ValueKind, CastTypeInfo, Op.Kind,
                         Op.SrcExpr.get(), &Op.BasePath, LPLoc, RPLoc));
}

ExprResult Sema::BuildCheriToOrFromCap(SourceLocation LParenLoc,
                                       SourceLocation KeywordLoc, bool IsToCap,
                                       QualType DestTy, TypeSourceInfo *TSInfo,
                                       SourceLocation RParenLoc, Expr *SubExpr) {
  // NOTE: __cheri_tocap and __cheri_fromcap are no-ops in both the hybrid and
  //       purecap ABI if both source and destination types are capabilities
  //       and the types are compatible.

  // Use getRealReferenceType() because getType() only returns T for T&
  const QualType SrcTy = SubExpr->getRealReferenceType(Context, false);
  // Dependent types not yet handled, would probably need a new AST node to
  // differentiate from normal C-style casts
  if (SrcTy->isDependentType()) {
    Diag(KeywordLoc, diag::err_cheri_to_from_cap_not_supported_in_templates)
        << IsToCap << SrcTy;
    return ExprError();
  }

  // We don't included __uintcap_t here since it should be be allowed to use
  // a __cheri_{to,from}cap on __uintcap_t
  const bool SrcIsCap = SrcTy->isCHERICapabilityType(Context, false);
  const bool DestIsCap = DestTy->isCHERICapabilityType(Context, false);
  CastKind Kind = CK_NoOp;
  if (IsToCap) {
    // __cheri_tocap
    if (!SrcTy->isPointerType()) {
      Diag(SubExpr->getBeginLoc(), diag::err_cheri_to_from_cap_invalid_source_type)
        << SrcTy << IsToCap;
      return ExprError();
    }
    if (!DestIsCap) {
      Diag(TSInfo->getTypeLoc().getBeginLoc(),
           diag::err_cheri_to_from_cap_invalid_target_type) << DestTy << IsToCap;
      return ExprError();
    }
    // No-op if SrcTy is a capability
    if (!SrcIsCap)
      Kind = CK_PointerToCHERICapability;

  } else {
    // __cheri_fromcap
    if (!SrcIsCap) {
      Diag(SubExpr->getBeginLoc(), diag::err_cheri_to_from_cap_invalid_source_type)
        << SrcTy << IsToCap;
      return ExprError();
    }
    if (!DestTy->isPointerType()) {
      Diag(TSInfo->getTypeLoc().getBeginLoc(),
           diag::err_cheri_to_from_cap_invalid_target_type) << DestTy << IsToCap;
      return ExprError();
    }
    // No-op if DestTy is a capability
    if (!DestIsCap)
      Kind = CK_CHERICapabilityToPointer;
  }

  // C++ checks if the types are exactly the same -> this will fail because
  // capability and non-capability Type* are different instances
  //
  // Types compatible source:
  //   if (getLangOpts().CPlusPlus)
  //     return hasSameType(LHS, RHS);
  //  return !mergeTypes(LHS, RHS, false, CompareUnqualified).isNull();

  if (!CheckCHERIAssignCompatible(DestTy, SrcTy, SubExpr)) {
    Diag(SubExpr->getBeginLoc(), diag::err_cheri_to_from_cap_unrelated_type)
         << IsToCap << SrcTy << DestTy;
    return ExprError();
  }

  // Warn about no-op cheri casts.
  if (Kind == CK_NoOp) {
    Diag(KeywordLoc, diag::warn_cheri_to_from_cap_noop)
      << IsToCap << SrcTy << DestTy
      << FixItHint::CreateRemoval(SourceRange(LParenLoc, RParenLoc));
    // If we are casting to void*
  }

  return CStyleCastExpr::Create(Context, DestTy, VK_RValue, Kind, SubExpr,
                                nullptr, TSInfo, LParenLoc, RParenLoc);
}

// Check if LHS and RHS are assign compatible for CHERI (ignoring capability
// qualifiers). Insert an implicit bitcast if necessary (when InsertBitCast is
// true - the default) and update RHSExpr to point to it.
//
// Two types LHS and RHS are assign compatible (ignoring capability qualifiers) if:
// - LHS == RHS
// - either of LHS or RHS is void*
//
// In the case of LHS being void*, an implicit bitcast from RHSExpr to void*
// will be inserted and RHSExpr updated to point to this ImplicitCastExpr.
bool Sema::CheckCHERIAssignCompatible(QualType LHS, QualType RHS, Expr *&RHSExpr, bool InsertBitCast) {
  // XXXAR: I had to modify mergeTypes() to add a IncludeCapabilityQualifier
  // flag because here we want to compare everything but the __capability
  // qualifier
  // XXXKG: I also extended mergeTypes() with a MergeVoidPtr flag to allow the
  // <-> void* case (and still get the checking of qualifiers).
  // XXXKG: Allow non-const to const assignment
  QualType MergedTy = Context.mergeTypes(
      LHS, RHS, /*OfBlockPointer=*/false, /*Unqualified=*/false,
      /*BlockReturnType=*/false, /*IncludeCapabilityQualifier=*/false,
      /*MergeVoidPtr=*/false, /*MergeLHSConst=*/false);
  if (MergedTy.isNull()) {
    // As a special case we allow changing the types if either:
    // - LHS or RHS is a pointer to void
    // - LHS has a const-qualified pointee type and the RHS pointee is not
    //   const-qualified
    MergedTy = Context.mergeTypes(
        LHS, RHS, /*OfBlockPointer=*/false, /*Unqualified=*/false,
        /*BlockReturnType=*/false, /*IncludeCapabilityQualifier=*/false,
        /*MergeVoidPtr=*/true, /*MergeLHSConst=*/true);
    if (!MergedTy.isNull()) {
      if (InsertBitCast) {
        // Insert a CK_BitCast to ensure we don't crash during codegen (see
        // https://github.com/CTSRD-CHERI/clang/issues/178)
        bool RHSIsCap = RHS->isCHERICapabilityType(Context, false);
        QualType BitCastTy = Context.getPointerType(
            LHS->getAs<PointerType>()->getPointeeType(),
            RHSIsCap ? ASTContext::PIK_Capability : ASTContext::PIK_Integer);
        RHSExpr = ImplicitCastExpr::Create(Context, BitCastTy, CK_BitCast,
                                           RHSExpr, nullptr, VK_RValue);
      }
      return true;
    }
    return false;
  }
  return true;
}

ExprResult Sema::BuildCheriOffsetOrAddress(SourceLocation LParenLoc,
                                           SourceLocation KeywordLoc,
                                           bool IsOffsetCast, QualType
                                           DestTy, TypeSourceInfo *TSInfo,
                                           SourceLocation RParenLoc, Expr
                                           *SubExpr) {

  CastKind Kind =
      IsOffsetCast ? CK_CHERICapabilityToOffset : CK_CHERICapabilityToAddress;

  // Check the source type
  // Use getRealReferenceType() because getType() only returns T for T&
  QualType SrcTy = SubExpr->getRealReferenceType(Context, false);
  // Dependent types not yet handled, would probably need a new AST node to
  // differentiate from normal C-style casts
  if (SrcTy->isDependentType()) {
    Diag(KeywordLoc, diag::err_cheri_addr_offset_not_supported_in_templates)
        << IsOffsetCast << SrcTy;
    return ExprError();
  }
  // __cheri_offset and __cheri_addr is valid for __uintcap_t as well
  bool SrcIsCap = SrcTy->isCHERICapabilityType(Context, true);
  if (!SrcIsCap) {
    // Note: __cheri_addr can be used on plain pointers since otherwise it would
    // be very difficult to write code that compiles both in hybrid and in
    // purecap mode. However, the offset cast only makes sense for capabilities!
    // XXXAR: Currently, __cheri_addr is allowed on references. Should we allow
    // this without an address-of operator first?
    if (IsOffsetCast || (!SrcTy->isPointerType() && !SrcTy->isReferenceType() &&
                         !SrcTy->isIntCapType())) {
      // XXXKG: What about functions?
      Diag(SubExpr->getBeginLoc(),
           diag::err_cheri_offset_addr_invalid_source_type)
          << SrcTy << IsOffsetCast;
      return ExprError();
    } else {
      // Casting from pointer to address in hybrid mode
      assert(!Context.getTargetInfo().areAllPointersCapabilities());
      Kind = CK_PointerToIntegral;
    }
  }

  // Check the destination type:
  // For __cheri_addr, output a more specific error message if DestTy is an
  // integral pointer type
  if (!IsOffsetCast) {
    if (DestTy->isPointerType()) {
      Diag(SubExpr->getBeginLoc(), diag::err_cheri_addr_ptr_type)
        << DestTy << (int)DestTy->getAs<PointerType>()->isCHERICapability();
      return ExprError();
    }
  }
  // Otherwise just check that it is a non-enum integer type
  bool DestIsInt = DestTy->isIntegerType() && !DestTy->isEnumeralType();
  if (!DestIsInt) {
    Diag(SubExpr->getBeginLoc(), diag::err_cheri_offset_addr_invalid_target_type)
      << DestTy << IsOffsetCast;
    return ExprError();
  }

  // Output warning about truncation if DestTy is smaller than CHERI cap pointer range
  auto& TI = Context.getTargetInfo();
  uint64_t PtrRange = TI.getPointerRangeForCHERICapability();
  uint64_t DestRange = Context.getTypeSize(DestTy);
  if (DestRange < PtrRange) {
    bool DestIsSigned = DestTy->isSignedIntegerOrEnumerationType();
    const char *minTy = TI.getTypeName(
                          TI.getLeastIntTypeByWidth(PtrRange, DestIsSigned)
                        );
    Diag(SubExpr->getBeginLoc(), diag::warn_cheri_offset_addr_smaller_target_type)
      << DestTy << minTy << IsOffsetCast;
  }

  return CStyleCastExpr::Create(Context, DestTy, VK_RValue, Kind, SubExpr,
                                nullptr, TSInfo, LParenLoc, RParenLoc);
}

ExprResult Sema::ActOnCheriCast(Scope *S, SourceLocation LParenLoc, tok::TokenKind Kind,
                                SourceLocation KeywordLoc, ParsedType Type,
                                SourceLocation RParenLoc, Expr *SubExpr) {
  if (Kind == tok::kw___cheri_cast) {
    Diag(KeywordLoc, diag::err_cheri_cast);
    return ExprError();
  }
  TypeSourceInfo *TSInfo = nullptr;
  QualType T = GetTypeFromParser(Type, &TSInfo);
  if (!TSInfo)
    TSInfo = Context.getTrivialTypeSourceInfo(T, LParenLoc);

  // Perform the default function/array to pointer decay first:
  ExprResult Decayed = DefaultFunctionArrayLvalueConversion(SubExpr);
  if (Decayed.isInvalid())
    return ExprError();
  SubExpr = Decayed.get();

  switch (Kind) {
  case tok::kw___cheri_tocap:
  case tok::kw___cheri_fromcap:
    return BuildCheriToOrFromCap(LParenLoc, KeywordLoc,
                                 Kind == tok::kw___cheri_tocap, T,
                                 TSInfo, RParenLoc, SubExpr);

  case tok::kw___cheri_offset:
  case tok::kw___cheri_addr:
    return BuildCheriOffsetOrAddress(LParenLoc, KeywordLoc,
                                     Kind == tok::kw___cheri_offset, T,
                                     TSInfo, RParenLoc, SubExpr);

  default:
    llvm_unreachable("Unknown CHERI cast!");
  }
}
