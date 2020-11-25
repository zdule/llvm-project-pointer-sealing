; NOTE: Assertions have been autogenerated by utils/update_test_checks.py UTC_ARGS: --function-signature --scrub-attributes --force-update
; DO NOT EDIT -- This file was generated from test/CodeGen/CHERI-Generic/Inputs/hoist-alloca.ll
; REQUIRES: asserts
; Check that we can hoist the csetbounds for a local alloca outside of loops
; We know that it's always tagged and unsealed so machinelicm should be able to
; to hoist the csetbounds instructions.
; TODO: for MIPS "simple-register-coalescing" moves the CheriBoundedStackPseudoImm back into the loop.
; In general this will be faster than loading from the stack, but it's probably worse
; than using a callee-saved register for loops with many iterations.

; Generated from this code:
; void call(int *src, int *dst);
;
; void hoist_alloca_uncond(int cond) {
;   int buf1[123];
;   int buf2[22];
;   for (int i = 0; i < 100; i++) {
;     call(buf1, buf2);
;   }
; }
;
; void hoist_alloca_cond(int cond) {
;   int buf1[123];
;   int buf2[22];
;   for (int i = 0; i < 100; i++) {
;     if (cond) {
;       call(buf1, buf2);
;     }
;   }
; }

; RUN: llc -mtriple=riscv32 --relocation-model=pic -target-abi il32pc64f -mattr=+xcheri,+cap-mode,+f -o %t.mir -stop-before=early-machinelicm < %s
; RUN: echo "DONOTAUTOGEN" | llc -mtriple=riscv32 --relocation-model=pic -target-abi il32pc64f -mattr=+xcheri,+cap-mode,+f -run-pass=early-machinelicm \
; RUN:    -debug-only=machinelicm %t.mir -o /dev/null 2>&1 | FileCheck --check-prefix=MACHINELICM-DBG %s
; Check that MachineLICM hoists the CheriBoundedStackPseudoImm (MIPS) / IncOffset+SetBounds (RISCV) instructions
; MACHINELICM-DBG-LABEL: ******** Pre-regalloc Machine LICM: hoist_alloca_uncond
; MACHINELICM-DBG: Hoisting [[INC:%[0-9]+]]:gpcr = CIncOffsetImm %stack.0.buf1, 0
; MACHINELICM-DBG-NEXT:  from %bb.2 to %bb.0
; MACHINELICM-DBG: Hoisting [[BOUNDS:%[0-9]+]]:gpcr = CSetBounds [[INC]]:gpcr, %{{[0-9]+}}:gpr
; MACHINELICM-DBG-NEXT:  from %bb.2 to %bb.0
; MACHINELICM-DBG: Hoisting [[INC:%[0-9]+]]:gpcr = CIncOffsetImm %stack.1.buf2, 0
; MACHINELICM-DBG-NEXT:  from %bb.2 to %bb.0
; MACHINELICM-DBG: Hoisting [[BOUNDS:%[0-9]+]]:gpcr = CSetBounds [[INC]]:gpcr, %{{[0-9]+}}:gpr
; MACHINELICM-DBG-NEXT:  from %bb.2 to %bb.0
; MACHINELICM-DBG-LABEL: ******** Pre-regalloc Machine LICM: hoist_alloca_cond
; MACHINELICM-DBG: Hoisting [[INC:%[0-9]+]]:gpcr = CIncOffsetImm %stack.0.buf1, 0
; MACHINELICM-DBG-NEXT:  from %bb.3 to %bb.0
; MACHINELICM-DBG: Hoisting [[BOUNDS:%[0-9]+]]:gpcr = CSetBounds [[INC]]:gpcr, %{{[0-9]+}}:gpr
; MACHINELICM-DBG-NEXT:  from %bb.3 to %bb.0
; MACHINELICM-DBG: Hoisting [[INC:%[0-9]+]]:gpcr = CIncOffsetImm %stack.1.buf2, 0
; MACHINELICM-DBG-NEXT:  from %bb.3 to %bb.0
; MACHINELICM-DBG: Hoisting [[BOUNDS:%[0-9]+]]:gpcr = CSetBounds [[INC]]:gpcr, %{{[0-9]+}}:gpr
; MACHINELICM-DBG-NEXT:  from %bb.3 to %bb.0

; RUN: llc -mtriple=riscv32 --relocation-model=pic -target-abi il32pc64f -mattr=+xcheri,+cap-mode,+f -O1 -o - < %s | FileCheck %s

define void @hoist_alloca_uncond(i32 signext %cond) local_unnamed_addr addrspace(200) nounwind {
; CHECK-LABEL: hoist_alloca_uncond:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    cincoffset csp, csp, -624
; CHECK-NEXT:    csc cra, 616(csp)
; CHECK-NEXT:    csc cs0, 608(csp)
; CHECK-NEXT:    csc cs1, 600(csp)
; CHECK-NEXT:    csc cs2, 592(csp)
; CHECK-NEXT:    addi s0, zero, 100
; CHECK-NEXT:    addi a0, zero, 492
; CHECK-NEXT:    cincoffset ca1, csp, 100
; CHECK-NEXT:    csetbounds cs2, ca1, a0
; CHECK-NEXT:    addi a0, zero, 88
; CHECK-NEXT:    cincoffset ca1, csp, 12
; CHECK-NEXT:    csetbounds cs1, ca1, a0
; CHECK-NEXT:  .LBB0_1: # %for.body
; CHECK-NEXT:    # =>This Inner Loop Header: Depth=1
; CHECK-NEXT:  .LBB0_3: # %for.body
; CHECK-NEXT:    # in Loop: Header=BB0_1 Depth=1
; CHECK-NEXT:    # Label of block must be emitted
; CHECK-NEXT:    auipcc ca2, %captab_pcrel_hi(call)
; CHECK-NEXT:    clc ca2, %pcrel_lo(.LBB0_3)(ca2)
; CHECK-NEXT:    cmove ca0, cs2
; CHECK-NEXT:    cmove ca1, cs1
; CHECK-NEXT:    cjalr ca2
; CHECK-NEXT:    addi s0, s0, -1
; CHECK-NEXT:    bnez s0, .LBB0_1
; CHECK-NEXT:  # %bb.2: # %for.cond.cleanup
; CHECK-NEXT:    clc cs2, 592(csp)
; CHECK-NEXT:    clc cs1, 600(csp)
; CHECK-NEXT:    clc cs0, 608(csp)
; CHECK-NEXT:    clc cra, 616(csp)
; CHECK-NEXT:    cincoffset csp, csp, 624
; CHECK-NEXT:    cret
entry:
  %buf1 = alloca [123 x i32], align 4, addrspace(200)
  %buf2 = alloca [22 x i32], align 4, addrspace(200)
  br label %for.body

for.cond.cleanup:                                 ; preds = %for.body
  ret void

for.body:                                         ; preds = %for.body, %entry
  %i.04 = phi i32 [ 0, %entry ], [ %inc, %for.body ]
  %arraydecay = getelementptr inbounds [123 x i32], [123 x i32] addrspace(200)* %buf1, i64 0, i64 0
  %arraydecay1 = getelementptr inbounds [22 x i32], [22 x i32] addrspace(200)* %buf2, i64 0, i64 0
  call void @call(i32 addrspace(200)* nonnull %arraydecay, i32 addrspace(200)* nonnull %arraydecay1)
  %inc = add nuw nsw i32 %i.04, 1
  %exitcond.not = icmp eq i32 %inc, 100
  br i1 %exitcond.not, label %for.cond.cleanup, label %for.body
}

declare void @call(i32 addrspace(200)*, i32 addrspace(200)*) local_unnamed_addr addrspace(200) nounwind

define void @hoist_alloca_cond(i32 signext %cond) local_unnamed_addr addrspace(200) nounwind {
; CHECK-LABEL: hoist_alloca_cond:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    cincoffset csp, csp, -624
; CHECK-NEXT:    csc cra, 616(csp)
; CHECK-NEXT:    csc cs0, 608(csp)
; CHECK-NEXT:    csc cs1, 600(csp)
; CHECK-NEXT:    csc cs2, 592(csp)
; CHECK-NEXT:    csc cs3, 584(csp)
; CHECK-NEXT:    seqz s0, a0
; CHECK-NEXT:    addi s1, zero, 100
; CHECK-NEXT:    addi a0, zero, 492
; CHECK-NEXT:    cincoffset ca1, csp, 92
; CHECK-NEXT:    csetbounds cs2, ca1, a0
; CHECK-NEXT:    addi a0, zero, 88
; CHECK-NEXT:    cincoffset ca1, csp, 4
; CHECK-NEXT:    csetbounds cs3, ca1, a0
; CHECK-NEXT:    j .LBB1_2
; CHECK-NEXT:  .LBB1_1: # %for.inc
; CHECK-NEXT:    # in Loop: Header=BB1_2 Depth=1
; CHECK-NEXT:    addi s1, s1, -1
; CHECK-NEXT:    beqz s1, .LBB1_4
; CHECK-NEXT:  .LBB1_2: # %for.body
; CHECK-NEXT:    # =>This Inner Loop Header: Depth=1
; CHECK-NEXT:    bnez s0, .LBB1_1
; CHECK-NEXT:  # %bb.3: # %if.then
; CHECK-NEXT:    # in Loop: Header=BB1_2 Depth=1
; CHECK-NEXT:  .LBB1_5: # %if.then
; CHECK-NEXT:    # in Loop: Header=BB1_2 Depth=1
; CHECK-NEXT:    # Label of block must be emitted
; CHECK-NEXT:    auipcc ca2, %captab_pcrel_hi(call)
; CHECK-NEXT:    clc ca2, %pcrel_lo(.LBB1_5)(ca2)
; CHECK-NEXT:    cmove ca0, cs2
; CHECK-NEXT:    cmove ca1, cs3
; CHECK-NEXT:    cjalr ca2
; CHECK-NEXT:    j .LBB1_1
; CHECK-NEXT:  .LBB1_4: # %for.cond.cleanup
; CHECK-NEXT:    clc cs3, 584(csp)
; CHECK-NEXT:    clc cs2, 592(csp)
; CHECK-NEXT:    clc cs1, 600(csp)
; CHECK-NEXT:    clc cs0, 608(csp)
; CHECK-NEXT:    clc cra, 616(csp)
; CHECK-NEXT:    cincoffset csp, csp, 624
; CHECK-NEXT:    cret
entry:
  %buf1 = alloca [123 x i32], align 4, addrspace(200)
  %buf2 = alloca [22 x i32], align 4, addrspace(200)
  %tobool.not = icmp eq i32 %cond, 0
  br label %for.body

for.cond.cleanup:                                 ; preds = %for.inc
  ret void

for.body:                                         ; preds = %for.inc, %entry
  %i.04 = phi i32 [ 0, %entry ], [ %inc, %for.inc ]
  br i1 %tobool.not, label %for.inc, label %if.then

if.then:                                          ; preds = %for.body
  %arraydecay = getelementptr inbounds [123 x i32], [123 x i32] addrspace(200)* %buf1, i64 0, i64 0
  %arraydecay1 = getelementptr inbounds [22 x i32], [22 x i32] addrspace(200)* %buf2, i64 0, i64 0
  call void @call(i32 addrspace(200)* nonnull %arraydecay, i32 addrspace(200)* nonnull %arraydecay1)
  br label %for.inc

for.inc:                                          ; preds = %for.body, %if.then
  %inc = add nuw nsw i32 %i.04, 1
  %exitcond.not = icmp eq i32 %inc, 100
  br i1 %exitcond.not, label %for.cond.cleanup, label %for.body
}
