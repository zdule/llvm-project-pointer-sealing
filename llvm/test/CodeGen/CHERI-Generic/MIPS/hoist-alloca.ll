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

; RUN: llc -mtriple=mips64 -mcpu=cheri128 -mattr=+cheri128 --relocation-model=pic -target-abi purecap -o %t.mir -stop-before=early-machinelicm < %s
; RUN: echo "DONOTAUTOGEN" | llc -mtriple=mips64 -mcpu=cheri128 -mattr=+cheri128 --relocation-model=pic -target-abi purecap -run-pass=early-machinelicm \
; RUN:    -debug-only=machinelicm %t.mir -o /dev/null 2>&1 | FileCheck --check-prefix=MACHINELICM-DBG %s
; Check that MachineLICM hoists the CheriBoundedStackPseudoImm (MIPS) / IncOffset+SetBounds (RISCV) instructions
; MACHINELICM-DBG-LABEL: ******** Pre-regalloc Machine LICM: hoist_alloca_uncond
; MACHINELICM-DBG: Hoisting %{{[0-9]+}}:cherigpr = CheriBoundedStackPseudoImm %stack.0.buf1, 0, 492
; MACHINELICM-DBG-NEXT:  from %bb.2 to %bb.0
; MACHINELICM-DBG: Hoisting %{{[0-9]+}}:cherigpr = CheriBoundedStackPseudoImm %stack.1.buf2, 0, 88
; MACHINELICM-DBG-NEXT:  from %bb.2 to %bb.0
; MACHINELICM-DBG-LABEL: ******** Pre-regalloc Machine LICM: hoist_alloca_cond
; MACHINELICM-DBG: Hoisting %{{[0-9]+}}:cherigpr = CheriBoundedStackPseudoImm %stack.0.buf1, 0, 492
; MACHINELICM-DBG-NEXT:  from %bb.3 to %bb.0
; MACHINELICM-DBG: Hoisting %{{[0-9]+}}:cherigpr = CheriBoundedStackPseudoImm %stack.1.buf2, 0, 88
; MACHINELICM-DBG-NEXT:  from %bb.3 to %bb.0

; RUN: llc -mtriple=mips64 -mcpu=cheri128 -mattr=+cheri128 --relocation-model=pic -target-abi purecap -O1 -o - < %s | FileCheck %s

define void @hoist_alloca_uncond(i32 signext %cond) local_unnamed_addr addrspace(200) nounwind {
; CHECK-LABEL: hoist_alloca_uncond:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    cincoffset $c11, $c11, -640
; CHECK-NEXT:    csd $16, $zero, 632($c11) # 8-byte Folded Spill
; CHECK-NEXT:    csc $c18, $zero, 608($c11) # 16-byte Folded Spill
; CHECK-NEXT:    csc $c17, $zero, 592($c11) # 16-byte Folded Spill
; CHECK-NEXT:    lui $1, %pcrel_hi(_CHERI_CAPABILITY_TABLE_-8)
; CHECK-NEXT:    daddiu $1, $1, %pcrel_lo(_CHERI_CAPABILITY_TABLE_-4)
; CHECK-NEXT:    cgetpccincoffset $c18, $1
; CHECK-NEXT:    addiu $16, $zero, 100
; CHECK-NEXT:  .LBB0_1: # %for.body
; CHECK-NEXT:    # =>This Inner Loop Header: Depth=1
; CHECK-NEXT:    clcbi $c12, %capcall20(call)($c18)
; CHECK-NEXT:    cincoffset $c3, $c11, 100
; CHECK-NEXT:    csetbounds $c3, $c3, 492
; CHECK-NEXT:    cincoffset $c4, $c11, 12
; CHECK-NEXT:    csetbounds $c4, $c4, 88
; CHECK-NEXT:    cjalr $c12, $c17
; CHECK-NEXT:    cgetnull $c13
; CHECK-NEXT:    addiu $16, $16, -1
; CHECK-NEXT:    bnez $16, .LBB0_1
; CHECK-NEXT:    nop
; CHECK-NEXT:  # %bb.2: # %for.cond.cleanup
; CHECK-NEXT:    clc $c17, $zero, 592($c11) # 16-byte Folded Reload
; CHECK-NEXT:    clc $c18, $zero, 608($c11) # 16-byte Folded Reload
; CHECK-NEXT:    cld $16, $zero, 632($c11) # 8-byte Folded Reload
; CHECK-NEXT:    cjr $c17
; CHECK-NEXT:    cincoffset $c11, $c11, 640
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
; CHECK-NEXT:    cincoffset $c11, $c11, -640
; CHECK-NEXT:    csd $17, $zero, 632($c11) # 8-byte Folded Spill
; CHECK-NEXT:    csd $16, $zero, 624($c11) # 8-byte Folded Spill
; CHECK-NEXT:    csc $c18, $zero, 608($c11) # 16-byte Folded Spill
; CHECK-NEXT:    csc $c17, $zero, 592($c11) # 16-byte Folded Spill
; CHECK-NEXT:    move $16, $4
; CHECK-NEXT:    lui $1, %pcrel_hi(_CHERI_CAPABILITY_TABLE_-8)
; CHECK-NEXT:    daddiu $1, $1, %pcrel_lo(_CHERI_CAPABILITY_TABLE_-4)
; CHECK-NEXT:    cgetpccincoffset $c18, $1
; CHECK-NEXT:    b .LBB1_2
; CHECK-NEXT:    addiu $17, $zero, 100
; CHECK-NEXT:  .LBB1_1: # %for.inc
; CHECK-NEXT:    # in Loop: Header=BB1_2 Depth=1
; CHECK-NEXT:    addiu $17, $17, -1
; CHECK-NEXT:    beqz $17, .LBB1_4
; CHECK-NEXT:    nop
; CHECK-NEXT:  .LBB1_2: # %for.body
; CHECK-NEXT:    # =>This Inner Loop Header: Depth=1
; CHECK-NEXT:    beqz $16, .LBB1_1
; CHECK-NEXT:    nop
; CHECK-NEXT:  # %bb.3: # %if.then
; CHECK-NEXT:    # in Loop: Header=BB1_2 Depth=1
; CHECK-NEXT:    clcbi $c12, %capcall20(call)($c18)
; CHECK-NEXT:    cincoffset $c3, $c11, 100
; CHECK-NEXT:    csetbounds $c3, $c3, 492
; CHECK-NEXT:    cincoffset $c4, $c11, 12
; CHECK-NEXT:    csetbounds $c4, $c4, 88
; CHECK-NEXT:    cjalr $c12, $c17
; CHECK-NEXT:    cgetnull $c13
; CHECK-NEXT:    b .LBB1_1
; CHECK-NEXT:    nop
; CHECK-NEXT:  .LBB1_4: # %for.cond.cleanup
; CHECK-NEXT:    clc $c17, $zero, 592($c11) # 16-byte Folded Reload
; CHECK-NEXT:    clc $c18, $zero, 608($c11) # 16-byte Folded Reload
; CHECK-NEXT:    cld $16, $zero, 624($c11) # 8-byte Folded Reload
; CHECK-NEXT:    cld $17, $zero, 632($c11) # 8-byte Folded Reload
; CHECK-NEXT:    cjr $c17
; CHECK-NEXT:    cincoffset $c11, $c11, 640
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
