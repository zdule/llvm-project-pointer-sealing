//===--- CGExprDynamicUnsealed.cpp - CodeGen for Dynamic Unsealed Exprs ---===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This contains code to emit DynamicUnsealed Exprs as LLVM code.
//
//===----------------------------------------------------------------------===//

#include "CGCheriCast.h"
#include "CodeGenFunction.h"
#include "CodeGenModule.h"
#include "ConstantEmitter.h"
#include "clang/AST/StmtVisitor.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Instructions.h"
#include <algorithm>
using namespace clang;
using namespace CodeGen;

//===----------------------------------------------------------------------===//
//                        Dynamic Unsealed Expression Emitter
//===----------------------------------------------------------------------===//

typedef std::pair<llvm::Value*, llvm::Value*> PointerOTypePair;

namespace  {
class DynamicUnsealedExprEmitter
  : public StmtVisitor<DynamicUnsealedExprEmitter, PointerOTypePair> {
  CodeGenFunction &CGF;
  CGBuilderTy &Builder;
public:
  DynamicUnsealedExprEmitter(CodeGenFunction &cgf)
    : CGF(cgf), Builder(CGF.Builder) {
  }

  //===--------------------------------------------------------------------===//
  //                            Visitor Methods
  //===--------------------------------------------------------------------===//

  PointerOTypePair Visit(Expr *E) {
    ApplyDebugLocation DL(CGF, E);
    return StmtVisitor<DynamicUnsealedExprEmitter, PointerOTypePair>::Visit(E);
  }

  PointerOTypePair VisitStmt(Stmt *S) {
    S->dump(llvm::errs(), CGF.getContext());
    llvm_unreachable("Stmt can't have DynamicUnsealed result type!");
  }

  PointerOTypePair VisitExpr(Expr *S);
  PointerOTypePair VisitConstantExpr(ConstantExpr *E) {
    // llvm_unreachable("No DynamicUnsealed ConstExprs!");
    /*
    if (llvm::Constant *Result = ConstantEmitter(CGF).tryEmitConstantExpr(E))
      return ComplexPairTy(Result->getAggregateElement(0U),
                           Result->getAggregateElement(1U));
    */
    return Visit(E->getSubExpr());
  }

  PointerOTypePair VisitParenExpr(ParenExpr *PE) { return Visit(PE->getSubExpr());}
  PointerOTypePair VisitGenericSelectionExpr(GenericSelectionExpr *GE) {
    return Visit(GE->getResultExpr());
  }
  PointerOTypePair
  VisitSubstNonTypeTemplateParmExpr(SubstNonTypeTemplateParmExpr *PE) {
    return Visit(PE->getReplacement());
  }
  /*
  PointerOTypePair emitConstant(const CodeGenFunction::ConstantEmission &Constant,
                             Expr *E) {
    assert(Constant && "not a constant");
    if (Constant.isReference())
      return EmitLoadOfLValue(Constant.getReferenceLValue(CGF, E),
                              E->getExprLoc());

    // XXXAR: this cast is needed because I had to change the return type to
    // Value* instead (see https://github.com/CTSRD-CHERI/llvm/issues/268)
    llvm::Constant *pair = cast<llvm::Constant>(Constant.getValue(CGF));
    return ComplexPairTy(pair->getAggregateElement(0U),
                         pair->getAggregateElement(1U));
  }
  */
  // FIXME: CompoundLiteralExpr

  PointerOTypePair EmitCast(CastKind CK, Expr *Op, QualType DestTy);
  PointerOTypePair VisitImplicitCastExpr(ImplicitCastExpr *E) {
    // Unlike for scalars, we don't have to worry about function->ptr demotion
    // here.
    return EmitCast(E->getCastKind(), E->getSubExpr(), E->getType());
  }
  PointerOTypePair VisitCastExpr(CastExpr *E) {
    if (const auto *ECE = dyn_cast<ExplicitCastExpr>(E))
      CGF.CGM.EmitExplicitCastExprType(ECE, &CGF);
    return EmitCast(E->getCastKind(), E->getSubExpr(), E->getType());
  }
  //PointerOTypePair VisitStmtExpr(const StmtExpr *E);

  PointerOTypePair VisitUnaryDeref(const Expr *E) {
    llvm_unreachable("Dynamic Unsealed LValues not supported!");
    // return EmitLoadOfLValue(E);
  }
  PointerOTypePair VisitUnaryPlus(const UnaryOperator *E) {
    return Visit(E->getSubExpr());
  }

  PointerOTypePair VisitUnaryAddrOf(const UnaryOperator *E) {
    // TODO: dz308: This is just copied code from scalar emitter
    llvm::Value *OType = EmitOtype(CGF.CGM, E->getType()->getPointeeType());
    if (isa<MemberPointerType>(E->getType())) // never sugared
      return PointerOTypePair(CGF.CGM.getMemberPointerConstant(E), OType);

    llvm::Value *Addr = CGF.EmitLValue(E->getSubExpr()).getPointer(CGF);
    auto &TI = CGF.getContext().getTargetInfo();
    if (TI.areAllPointersCapabilities()) {
      assert(Addr->getType()->getPointerAddressSpace() ==
             CGF.CGM.getTargetCodeGenInfo().getCHERICapabilityAS());
    }
    if (CGF.getLangOpts().getCheriBounds() >= LangOptions::CBM_SubObjectsSafe) {
      auto BoundedAddr = CGF.setCHERIBoundsOnAddrOf(
          Addr, E->getSubExpr()->getType(), E->getSubExpr(), E);
      assert(BoundedAddr->getType() == Addr->getType());
      Addr = BoundedAddr;
    }
    return PointerOTypePair(Addr, OType);
  }

  PointerOTypePair VisitUnaryExtension(const UnaryOperator *E) {
    return Visit(E->getSubExpr());
  }

  PointerOTypePair VisitImplicitValueInitExpr(ImplicitValueInitExpr *E) {
    llvm_unreachable("Implicit initialisation not supported yet for Dynamic Unsealed!");
    /*
    QualType Elem = E->getType()->castAs<ComplexType>()->getElementType();
    llvm::Constant *Null =
                       llvm::Constant::getNullValue(CGF.ConvertType(Elem));
    return ComplexPairTy(Null, Null);
     */
  }

  struct BinOpInfo {
    PointerOTypePair LHS;
    PointerOTypePair RHS;
    QualType Ty;  // Computation Type.
    const Expr *E;
  };

  BinOpInfo EmitBinOps(const BinaryOperator *E);

  PointerOTypePair EmitBinAdd(const BinOpInfo &Op);
  PointerOTypePair EmitBinSub(const BinOpInfo &Op);


  PointerOTypePair VisitBinAdd(const BinaryOperator *E) {
    return EmitBinAdd(EmitBinOps(E));
  }
  PointerOTypePair VisitBinSub(const BinaryOperator *E) {
    return EmitBinSub(EmitBinOps(E));
  }

  PointerOTypePair VisitBinComma(const BinaryOperator *E);

  PointerOTypePair VisitCallExpr(const CallExpr *E) {
    CGCallee callee = CGF.EmitCallee(E->getCallee());
    if (callee.isBuiltin()) {
      return CGF.EmitBuiltinExpr(callee.getBuiltinDecl(), callee.getBuiltinID(),
                             E, ReturnValueSlot()).getComplexVal();
    } else {
      // This should throw an error
      return VisitStmt(const_cast<CallExpr*>(E));
    }
  }


  PointerOTypePair
  VisitAbstractConditionalOperator(const AbstractConditionalOperator *CO);
  PointerOTypePair VisitChooseExpr(ChooseExpr *CE);
};
}  // end anonymous namespace.

//===----------------------------------------------------------------------===//
//                            Visitor Methods
//===----------------------------------------------------------------------===//

PointerOTypePair DynamicUnsealedExprEmitter::VisitExpr(Expr *E) {
  CGF.ErrorUnsupported(E, "dynamic unsealed expression");
  llvm_unreachable("not supported");
  /*
  llvm::Type *EltTy =
    CGF.ConvertType(getComplexType(E->getType())->getElementType());
  llvm::Value *U = llvm::UndefValue::get(EltTy);
  return ComplexPairTy(U, U);
   */
}

PointerOTypePair DynamicUnsealedExprEmitter::EmitCast(CastKind CK, Expr *E,
                                           QualType DestTy) {
  switch (CK) {
  case CK_Dependent: llvm_unreachable("dependent cast kind in IR gen!");

  // Atomic to non-atomic casts may be more than a no-op for some platforms and
  // for some types.
  case CK_NoOp:
    return Visit(E);
  case CK_BitCast: {
    PointerOTypePair SubVal = Visit(E);
    SubVal.first = Builder.CreateBitCast(SubVal.first, CGF.ConvertType(DestTy));
    return SubVal;
  }
  case CK_DynamicSealedToDynamicUnsealedPointerCast: {
    llvm::Value *InCap = CGF.EmitScalarExpr(E);
    return UnsealDynamicCapability(CGF, InCap, E->getType()->castAs<PointerType>());
  }
  case CK_NullToPointer: {
    llvm::Value *NullConstant = CGF.CGM.getNullPointer(
        cast<llvm::PointerType>(CGF.ConvertType(DestTy)), DestTy);
    return PointerOTypePair(NullConstant,
                            EmitOtype(CGF.CGM, E->getType()->getPointeeType()));
  }
  case CK_ArrayToPointerDecay: {
    llvm::Value *Ptr = CGF.EmitArrayToPointerDecay(E).getPointer();
    QualType Ty = CGF.getContext().getArrayDecayedType(E->getType())->getPointeeType();
    return PointerOTypePair(Ptr, EmitOtype(CGF.CGM, Ty));
  }
  case CK_FunctionToPointerDecay: { // TODO: This was copied from scalar expression :(
    llvm::Value *Addr = CGF.EmitLValue(E).getPointer(CGF);
    llvm::Type *AddrTy = Addr->getType();
    auto &TI = CGF.getContext().getTargetInfo();
    if (TI.areAllPointersCapabilities()) {
      assert(AddrTy->getPointerAddressSpace() ==
             CGF.CGM.getTargetCodeGenInfo().getCHERICapabilityAS());
    }
    return PointerOTypePair(Addr,
                            EmitOtype(CGF.CGM, E->getType()));
  }
  default:
    llvm_unreachable("invalid cast kind for DynamicUnsealed value");
  }
  llvm_unreachable("unknown cast resulting in DynamicUnsealed value");
}

PointerOTypePair DynamicUnsealedExprEmitter::EmitBinAdd(const BinOpInfo &Op) {
  llvm::Value *ResPtr, *ResOType;
  QualType PtrType = CGF.CGM.getContext().getPointerTypeSealedAs(Op.Ty, PSK_Unsealed);
  ResPtr = CGF.EmitPtrBinOp(Op.LHS.first, Op.RHS.first, PtrType, BO_Add, Op.E);
  ResOType = Op.LHS.second != nullptr ? Op.LHS.second : Op.RHS.second;
  return PointerOTypePair(ResPtr, ResOType);
}

PointerOTypePair DynamicUnsealedExprEmitter::EmitBinSub(const BinOpInfo &Op) {
  llvm::Value *ResPtr, *ResOType;
  QualType PtrType = CGF.CGM.getContext().getPointerTypeSealedAs(Op.Ty, PSK_Unsealed);
  ResPtr = CGF.EmitPtrBinOp(Op.LHS.first, Op.RHS.first, PtrType, BO_Sub, Op.E);
  ResOType = Op.LHS.second != nullptr ? Op.LHS.second : Op.RHS.second;
  return PointerOTypePair(ResPtr, ResOType);
}

DynamicUnsealedExprEmitter::BinOpInfo
DynamicUnsealedExprEmitter::EmitBinOps(const BinaryOperator *E) {
  BinOpInfo Ops;
  auto EmitPointerOTypePair = [Emitter=this](Expr *E) {
    if (E->getType()->isPointerType()) {
      assert(E->getType()->castAs<PointerType>()->getSealingKind() ==
             PSK_DynamicUnsealed);
      return Emitter->Visit(E);
    }
    else {
      assert(E->getType()->isIntegerType());
      return PointerOTypePair(Emitter->CGF.EmitScalarExpr(E), nullptr);
    }
  };
  Ops.LHS = EmitPointerOTypePair(E->getLHS());
  Ops.RHS = EmitPointerOTypePair(E->getRHS());
  assert(Ops.LHS.second != nullptr || Ops.RHS.second != nullptr);
  Ops.Ty = E->getType();
  Ops.E = E;
  return Ops;
}

PointerOTypePair DynamicUnsealedExprEmitter::VisitBinComma(const BinaryOperator *E) {
  CGF.EmitIgnoredExpr(E->getLHS());
  return Visit(E->getRHS());
}

PointerOTypePair DynamicUnsealedExprEmitter::
VisitAbstractConditionalOperator(const AbstractConditionalOperator *E) {
  llvm::BasicBlock *LHSBlock = CGF.createBasicBlock("cond.true");
  llvm::BasicBlock *RHSBlock = CGF.createBasicBlock("cond.false");
  llvm::BasicBlock *ContBlock = CGF.createBasicBlock("cond.end");

  // Bind the common expression if necessary.
  CodeGenFunction::OpaqueValueMapping binding(CGF, E);


  CodeGenFunction::ConditionalEvaluation eval(CGF);
  CGF.EmitBranchOnBoolExpr(E->getCond(), LHSBlock, RHSBlock,
                           CGF.getProfileCount(E));

  eval.begin(CGF);
  CGF.EmitBlock(LHSBlock);
  CGF.incrementProfileCounter(E);
  PointerOTypePair LHS = Visit(E->getTrueExpr());
  LHSBlock = Builder.GetInsertBlock();
  CGF.EmitBranch(ContBlock);
  eval.end(CGF);

  eval.begin(CGF);
  CGF.EmitBlock(RHSBlock);
  PointerOTypePair RHS = Visit(E->getFalseExpr());
  RHSBlock = Builder.GetInsertBlock();
  CGF.EmitBlock(ContBlock);
  eval.end(CGF);

  // Create a PHI node for the pointer.
  llvm::PHINode *PtrPN = Builder.CreatePHI(LHS.first->getType(), 2, "cond.r");
  PtrPN->addIncoming(LHS.first, LHSBlock);
  PtrPN->addIncoming(RHS.first, RHSBlock);

  // Create a PHI node for the otype.
  llvm::PHINode *OTypePN = Builder.CreatePHI(LHS.second->getType(), 2, "cond.i");
  OTypePN->addIncoming(LHS.second, LHSBlock);
  OTypePN->addIncoming(RHS.second, RHSBlock);

  return PointerOTypePair(PtrPN, OTypePN);
}

PointerOTypePair DynamicUnsealedExprEmitter::VisitChooseExpr(ChooseExpr *E) {
  return Visit(E->getChosenSubExpr());
}

//===----------------------------------------------------------------------===//
//                         Entry Point into this File
//===----------------------------------------------------------------------===//

PointerOTypePair CodeGenFunction::EmitDynamicUnsealedExpr(const Expr *E) {
  assert(E && E->getType()->isPointerType() &&
         E->getType()->castAs<PointerType>()->getSealingKind() == PSK_DynamicUnsealed &&
         "Invalid DynamicUnsealed expression to emit");
  return DynamicUnsealedExprEmitter(*this).Visit(const_cast<Expr *>(E));
}