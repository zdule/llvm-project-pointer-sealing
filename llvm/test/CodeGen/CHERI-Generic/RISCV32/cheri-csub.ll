; NOTE: Assertions have been autogenerated by utils/update_test_checks.py UTC_ARGS: --function-signature --scrub-attributes --force-update
; DO NOT EDIT -- This file was generated from test/CodeGen/CHERI-Generic/Inputs/cheri-csub.ll
; RUN: llc -mtriple=riscv32 --relocation-model=pic -target-abi ilp32f -mattr=+xcheri,+f %s -o - | FileCheck %s --check-prefix=HYBRID
; RUN: llc -mtriple=riscv32 --relocation-model=pic -target-abi il32pc64f -mattr=+xcheri,+cap-mode,+f %s -o - | FileCheck %s --check-prefix=PURECAP

define i32 @subp(i8 addrspace(200)* readnone %a, i8 addrspace(200)* readnone %b) nounwind {
; HYBRID-LABEL: subp:
; HYBRID:       # %bb.0: # %entry
; HYBRID-NEXT:    csub a0, ca0, ca1
; HYBRID-NEXT:    ret
;
; PURECAP-LABEL: subp:
; PURECAP:       # %bb.0: # %entry
; PURECAP-NEXT:    csub a0, ca0, ca1
; PURECAP-NEXT:    cret
entry:
  %0 = tail call i32 @llvm.cheri.cap.diff.i32(i8 addrspace(200)* %a, i8 addrspace(200)* %b)
  ret i32 %0
}

declare i32 @llvm.cheri.cap.diff.i32(i8 addrspace(200)*, i8 addrspace(200)*)
