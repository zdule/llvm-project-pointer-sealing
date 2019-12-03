; NOTE: Assertions have been autogenerated by utils/update_llc_test_checks.py
; RUNs: %cheri_purecap_llc -cheri-cap-table-abi=pcrel %s -o - -O0 -print-before=atomic-expand -print-after=atomic-expand -debug-only=atomic-expand
; RUN: %cheri_purecap_llc -verify-machineinstrs -cheri-cap-table-abi=pcrel %s -o - -O2 | FileCheck %s -enable-var-scope
; ModuleID = 'atomic.c'

@cap = common addrspace(200) global i32 addrspace(200)* null, align 32

declare void @test(i32 addrspace(200)* nocapture %cap, i1 %bool)

define i32 @cmpxchg_null_ptr(i32 addrspace(200)* nocapture %exp, i32 addrspace(200)* %newval) nounwind {
; CHECK-LABEL: cmpxchg_null_ptr:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    cincoffset $c11, $c11, -[[#STACKFRAME_SIZE:]]
; CHECK-NEXT:    csc $c17, $zero, 0($c11)
; CHECK-NEXT:    sync
; CHECK-NEXT:    cgetnull $c2
; CHECK-NEXT:  .LBB0_1: # %entry
; CHECK-NEXT:    # =>This Inner Loop Header: Depth=1
; CHECK-NEXT:    cllc $c1, $c2
; CHECK-NEXT:    ceq $1, $c1, $c3
; CHECK-NEXT:    beqz $1, .LBB0_3
; CHECK-NEXT:    nop
; CHECK-NEXT:  # %bb.2: # %entry
; CHECK-NEXT:    # in Loop: Header=BB0_1 Depth=1
; CHECK-NEXT:    cscc $1, $c4, $c2
; CHECK-NEXT:    beqz $1, .LBB0_1
; CHECK-NEXT:    nop
; CHECK-NEXT:  .LBB0_3: # %entry
; CHECK-NEXT:    lui $1, %pcrel_hi(_CHERI_CAPABILITY_TABLE_-8)
; CHECK-NEXT:    daddiu $1, $1, %pcrel_lo(_CHERI_CAPABILITY_TABLE_-4)
; CHECK-NEXT:    cgetpccincoffset $c2, $1
; CHECK-NEXT:    ceq $4, $c1, $c3
; CHECK-NEXT:    sync
; CHECK-NEXT:    clcbi $c12, %capcall20(test)($c2)
; CHECK-NEXT:    cjalr $c12, $c17
; CHECK-NEXT:    cmove $c3, $c1
; CHECK-NEXT:    addiu $2, $zero, 42
; CHECK-NEXT:    clc $c17, $zero, 0($c11)
; CHECK-NEXT:    cjr $c17
; CHECK-NEXT:    cincoffset $c11, $c11, [[#STACKFRAME_SIZE]]
; Note: cannot use the null register for the pointer operand since in cllc/cscc it means $ddc:
entry:
  %0 = cmpxchg i32 addrspace(200)* addrspace(200)* null, i32 addrspace(200)* %exp, i32 addrspace(200)* %newval seq_cst seq_cst
  %1 = extractvalue { i32 addrspace(200)*, i1 } %0, 0
  %2 = extractvalue { i32 addrspace(200)*, i1 } %0, 1
  call void @test(i32 addrspace(200)* nocapture %1, i1 %2)
  ret i32 42
}

define i32 @cmpxchg_null_exp(i32 addrspace(200)* %newval) nounwind {
; CHECK-LABEL: cmpxchg_null_exp:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    cincoffset $c11, $c11, -[[#STACKFRAME_SIZE:]]
; CHECK-NEXT:    csc $c17, $zero, 0($c11)
; CHECK-NEXT:    lui $1, %pcrel_hi(_CHERI_CAPABILITY_TABLE_-8)
; CHECK-NEXT:    daddiu $1, $1, %pcrel_lo(_CHERI_CAPABILITY_TABLE_-4)
; CHECK-NEXT:    cgetpccincoffset $c2, $1
; CHECK-NEXT:    clcbi $c4, %captab20(cap)($c2)
; CHECK-NEXT:    sync
; CHECK-NEXT:  .LBB1_1: # %entry
; CHECK-NEXT:    # =>This Inner Loop Header: Depth=1
; CHECK-NEXT:    cllc $c1, $c4
; CHECK-NEXT:    ceq $1, $c1, $cnull
; CHECK-NEXT:    beqz $1, .LBB1_3
; CHECK-NEXT:    nop
; CHECK-NEXT:  # %bb.2: # %entry
; CHECK-NEXT:    # in Loop: Header=BB1_1 Depth=1
; CHECK-NEXT:    cscc $1, $c3, $c4
; CHECK-NEXT:    beqz $1, .LBB1_1
; CHECK-NEXT:    nop
; CHECK-NEXT:  .LBB1_3: # %entry
; CHECK-NEXT:    ceq $4, $c1, $cnull
; CHECK-NEXT:    sync
; CHECK-NEXT:    clcbi $c12, %capcall20(test)($c2)
; CHECK-NEXT:    cjalr $c12, $c17
; CHECK-NEXT:    cmove $c3, $c1
; CHECK-NEXT:    addiu $2, $zero, 42
; CHECK-NEXT:    clc $c17, $zero, 0($c11)
; CHECK-NEXT:    cjr $c17
; CHECK-NEXT:    cincoffset $c11, $c11, [[#STACKFRAME_SIZE]]
; This used to emit a cgetnull $c5
entry:
  %0 = cmpxchg i32 addrspace(200)* addrspace(200)* @cap, i32 addrspace(200)* null, i32 addrspace(200)* %newval seq_cst seq_cst
  %1 = extractvalue { i32 addrspace(200)*, i1 } %0, 0
  %2 = extractvalue { i32 addrspace(200)*, i1 } %0, 1
  call void @test(i32 addrspace(200)* nocapture %1, i1 %2)
  ret i32 42
}

define i32 @cmpxchg_null_newval(i32 addrspace(200)* %exp) nounwind {
; CHECK-LABEL: cmpxchg_null_newval:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    cincoffset $c11, $c11, -[[#STACKFRAME_SIZE:]]
; CHECK-NEXT:    csc $c17, $zero, 0($c11)
; CHECK-NEXT:    lui $1, %pcrel_hi(_CHERI_CAPABILITY_TABLE_-8)
; CHECK-NEXT:    daddiu $1, $1, %pcrel_lo(_CHERI_CAPABILITY_TABLE_-4)
; CHECK-NEXT:    cgetpccincoffset $c2, $1
; CHECK-NEXT:    clcbi $c4, %captab20(cap)($c2)
; CHECK-NEXT:    sync
; CHECK-NEXT:  .LBB2_1: # %entry
; CHECK-NEXT:    # =>This Inner Loop Header: Depth=1
; CHECK-NEXT:    cllc $c1, $c4
; CHECK-NEXT:    ceq $1, $c1, $c3
; CHECK-NEXT:    beqz $1, .LBB2_3
; CHECK-NEXT:    nop
; CHECK-NEXT:  # %bb.2: # %entry
; CHECK-NEXT:    # in Loop: Header=BB2_1 Depth=1
; CHECK-NEXT:    cscc $1, $cnull, $c4
; CHECK-NEXT:    beqz $1, .LBB2_1
; CHECK-NEXT:    nop
; CHECK-NEXT:  .LBB2_3: # %entry
; CHECK-NEXT:    ceq $4, $c1, $c3
; CHECK-NEXT:    sync
; CHECK-NEXT:    clcbi $c12, %capcall20(test)($c2)
; CHECK-NEXT:    cjalr $c12, $c17
; CHECK-NEXT:    cmove $c3, $c1
; CHECK-NEXT:    addiu $2, $zero, 42
; CHECK-NEXT:    clc $c17, $zero, 0($c11)
; CHECK-NEXT:    cjr $c17
; CHECK-NEXT:    cincoffset $c11, $c11, [[#STACKFRAME_SIZE]]
; This used to emit a cgetnull $c5
entry:
  %0 = cmpxchg i32 addrspace(200)* addrspace(200)* @cap, i32 addrspace(200)* %exp, i32 addrspace(200)* null seq_cst seq_cst
  %1 = extractvalue { i32 addrspace(200)*, i1 } %0, 0
  %2 = extractvalue { i32 addrspace(200)*, i1 } %0, 1
  call void @test(i32 addrspace(200)* nocapture %1, i1 %2)
  ret i32 42
}


define i32 addrspace(200)* @load_atomic_null_ptr() nounwind {
; Cannot use NULL register as the operand here since zero encodes $ddc
; CHECK-LABEL: load_atomic_null_ptr:
; CHECK:       # %bb.0:
; CHECK-NEXT:    cgetnull $c1
; CHECK-NEXT:    clc $c3, $zero, 0($c1)
; CHECK-NEXT:    sync
; CHECK-NEXT:    cjr $c17
; CHECK-NEXT:    nop
  %x = load atomic i32 addrspace(200)*, i32 addrspace(200)* addrspace(200)* null seq_cst, align 32
  ret i32 addrspace(200)* %x
}
define void @store_atomic_null_ptr(i32 addrspace(200)* %value) nounwind {
; Cannot use NULL register as the operand here since zero encodes $ddc
; CHECK-LABEL: store_atomic_null_ptr:
; CHECK:       # %bb.0:
; CHECK-NEXT:    sync
; CHECK-NEXT:    cgetnull $c1
; CHECK-NEXT:    csc $c3, $zero, 0($c1)
; CHECK-NEXT:    sync
; CHECK-NEXT:    cjr $c17
; CHECK-NEXT:    nop
  store atomic i32 addrspace(200)* %value, i32 addrspace(200)* addrspace(200)* null seq_cst, align 32
  ret void
}
define void @store_atomic_null_value(i32 addrspace(200)* addrspace(200)* %ptr) nounwind {
; This used to emit a cgetnull for the value.
; CHECK-LABEL: store_atomic_null_value:
; CHECK:       # %bb.0:
; CHECK-NEXT:    sync
; CHECK-NEXT:    csc $cnull, $zero, 0($c3)
; CHECK-NEXT:    sync
; CHECK-NEXT:    cjr $c17
; CHECK-NEXT:    nop
  store atomic i32 addrspace(200)* null, i32 addrspace(200)* addrspace(200)* %ptr seq_cst, align 32
  ret void
}

define i32 addrspace(200)* @atomic_fetch_swap_null_value(i32 addrspace(200)* addrspace(200)* %ptr) nounwind {
; This used to emit a cgetnull for the value.
; CHECK-LABEL: atomic_fetch_swap_null_value:
; CHECK:       # %bb.0:
; CHECK-NEXT:    .insn
; CHECK-NEXT:  .LBB6_1: # =>This Inner Loop Header: Depth=1
; CHECK-NEXT:    cllc $c1, $c3
; CHECK-NEXT:    cscc $1, $cnull, $c3
; CHECK-NEXT:    beqz $1, .LBB6_1
; CHECK-NEXT:    nop
; CHECK-NEXT:  # %bb.2:
; CHECK-NEXT:    sync
; CHECK-NEXT:    cjr $c17
; CHECK-NEXT:    cmove $c3, $c1
  %t1 = atomicrmw xchg i32 addrspace(200)* addrspace(200)* %ptr, i32 addrspace(200)* null acquire
  ret i32 addrspace(200)* %t1
}

define i32 addrspace(200)* @atomic_fetch_swap_null_ptr(i32 addrspace(200)* %value) nounwind {
; Cannot use $cnull fr the ptr since zero encodes $ddc
; CHECK-LABEL: atomic_fetch_swap_null_ptr:
; CHECK:       # %bb.0:
; CHECK-NEXT:    cgetnull $c2
; CHECK-NEXT:  .LBB7_1: # =>This Inner Loop Header: Depth=1
; CHECK-NEXT:    cllc $c1, $c2
; CHECK-NEXT:    cscc $1, $c3, $c2
; CHECK-NEXT:    beqz $1, .LBB7_1
; CHECK-NEXT:    nop
; CHECK-NEXT:  # %bb.2:
; CHECK-NEXT:    sync
; CHECK-NEXT:    cjr $c17
; CHECK-NEXT:    cmove $c3, $c1
  %t1 = atomicrmw xchg i32 addrspace(200)* addrspace(200)* null, i32 addrspace(200)* %value acquire
  ret i32 addrspace(200)* %t1
}

