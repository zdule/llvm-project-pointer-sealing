; NOTE: Assertions have been autogenerated by utils/update_test_checks.py UTC_ARGS: --force-update --function-signature --scrub-attributes
; DO NOT EDIT -- This file was generated from test/CodeGen/CHERI-Generic/Inputs/intrinsics.ll
; RUN: %cheri128_purecap_llc %s -o - < %s | FileCheck %s --check-prefix=PURECAP
; RUN: %cheri128_llc -o - < %s | FileCheck %s --check-prefix=HYBRID
; Check that the target-independent CHERI intrinsics are support for all architectures
; The grouping/ordering in this test is based on the RISC-V instruction listing
; in the CHERI ISA specification (Appendix C.1 in ISAv7).

; Capability-Inspection Instructions

declare i64 @llvm.cheri.cap.perms.get.i64(i8 addrspace(200)*)
declare i64 @llvm.cheri.cap.type.get.i64(i8 addrspace(200)*)
declare i64 @llvm.cheri.cap.base.get.i64(i8 addrspace(200)*)
declare i64 @llvm.cheri.cap.length.get.i64(i8 addrspace(200)*)
declare i1 @llvm.cheri.cap.tag.get(i8 addrspace(200)*)
declare i1 @llvm.cheri.cap.sealed.get(i8 addrspace(200)*)
declare i64 @llvm.cheri.cap.offset.get.i64(i8 addrspace(200)*)
declare i64 @llvm.cheri.cap.flags.get.i64(i8 addrspace(200)*)
declare i64 @llvm.cheri.cap.address.get.i64(i8 addrspace(200)*)

define i64 @perms_get(i8 addrspace(200)* %cap) nounwind {
; PURECAP-LABEL: perms_get:
; PURECAP:       # %bb.0:
; PURECAP-NEXT:    cjr $c17
; PURECAP-NEXT:    cgetperm $2, $c3
;
; HYBRID-LABEL: perms_get:
; HYBRID:       # %bb.0:
; HYBRID-NEXT:    jr $ra
; HYBRID-NEXT:    cgetperm $2, $c3
  %perms = call i64 @llvm.cheri.cap.perms.get.i64(i8 addrspace(200)* %cap)
  ret i64 %perms
}

define i64 @type_get(i8 addrspace(200)* %cap) nounwind {
; PURECAP-LABEL: type_get:
; PURECAP:       # %bb.0:
; PURECAP-NEXT:    cjr $c17
; PURECAP-NEXT:    cgettype $2, $c3
;
; HYBRID-LABEL: type_get:
; HYBRID:       # %bb.0:
; HYBRID-NEXT:    jr $ra
; HYBRID-NEXT:    cgettype $2, $c3
  %type = call i64 @llvm.cheri.cap.type.get.i64(i8 addrspace(200)* %cap)
  ret i64 %type
}

define i64 @base_get(i8 addrspace(200)* %cap) nounwind {
; PURECAP-LABEL: base_get:
; PURECAP:       # %bb.0:
; PURECAP-NEXT:    cjr $c17
; PURECAP-NEXT:    cgetbase $2, $c3
;
; HYBRID-LABEL: base_get:
; HYBRID:       # %bb.0:
; HYBRID-NEXT:    jr $ra
; HYBRID-NEXT:    cgetbase $2, $c3
  %base = call i64 @llvm.cheri.cap.base.get.i64(i8 addrspace(200)* %cap)
  ret i64 %base
}

define i64 @length_get(i8 addrspace(200)* %cap) nounwind {
; PURECAP-LABEL: length_get:
; PURECAP:       # %bb.0:
; PURECAP-NEXT:    cjr $c17
; PURECAP-NEXT:    cgetlen $2, $c3
;
; HYBRID-LABEL: length_get:
; HYBRID:       # %bb.0:
; HYBRID-NEXT:    jr $ra
; HYBRID-NEXT:    cgetlen $2, $c3
  %length = call i64 @llvm.cheri.cap.length.get.i64(i8 addrspace(200)* %cap)
  ret i64 %length
}

define i64 @tag_get(i8 addrspace(200)* %cap) nounwind {
; PURECAP-LABEL: tag_get:
; PURECAP:       # %bb.0:
; PURECAP-NEXT:    cjr $c17
; PURECAP-NEXT:    cgettag $2, $c3
;
; HYBRID-LABEL: tag_get:
; HYBRID:       # %bb.0:
; HYBRID-NEXT:    jr $ra
; HYBRID-NEXT:    cgettag $2, $c3
  %tag = call i1 @llvm.cheri.cap.tag.get(i8 addrspace(200)* %cap)
  %tag.zext = zext i1 %tag to i64
  ret i64 %tag.zext
}

define i64 @sealed_get(i8 addrspace(200)* %cap) nounwind {
; PURECAP-LABEL: sealed_get:
; PURECAP:       # %bb.0:
; PURECAP-NEXT:    cjr $c17
; PURECAP-NEXT:    cgetsealed $2, $c3
;
; HYBRID-LABEL: sealed_get:
; HYBRID:       # %bb.0:
; HYBRID-NEXT:    jr $ra
; HYBRID-NEXT:    cgetsealed $2, $c3
  %sealed = call i1 @llvm.cheri.cap.sealed.get(i8 addrspace(200)* %cap)
  %sealed.zext = zext i1 %sealed to i64
  ret i64 %sealed.zext
}

define i64 @offset_get(i8 addrspace(200)* %cap) nounwind {
; PURECAP-LABEL: offset_get:
; PURECAP:       # %bb.0:
; PURECAP-NEXT:    cjr $c17
; PURECAP-NEXT:    cgetoffset $2, $c3
;
; HYBRID-LABEL: offset_get:
; HYBRID:       # %bb.0:
; HYBRID-NEXT:    jr $ra
; HYBRID-NEXT:    cgetoffset $2, $c3
  %offset = call i64 @llvm.cheri.cap.offset.get.i64(i8 addrspace(200)* %cap)
  ret i64 %offset
}

define i64 @flags_get(i8 addrspace(200)* %cap) nounwind {
; PURECAP-LABEL: flags_get:
; PURECAP:       # %bb.0:
; PURECAP-NEXT:    cjr $c17
; PURECAP-NEXT:    cgetflags $2, $c3
;
; HYBRID-LABEL: flags_get:
; HYBRID:       # %bb.0:
; HYBRID-NEXT:    jr $ra
; HYBRID-NEXT:    cgetflags $2, $c3
  %flags = call i64 @llvm.cheri.cap.flags.get.i64(i8 addrspace(200)* %cap)
  ret i64 %flags
}

define i64 @address_get(i8 addrspace(200)* %cap) nounwind {
; PURECAP-LABEL: address_get:
; PURECAP:       # %bb.0:
; PURECAP-NEXT:    cjr $c17
; PURECAP-NEXT:    cgetaddr $2, $c3
;
; HYBRID-LABEL: address_get:
; HYBRID:       # %bb.0:
; HYBRID-NEXT:    jr $ra
; HYBRID-NEXT:    cgetaddr $2, $c3
  %address = call i64 @llvm.cheri.cap.address.get.i64(i8 addrspace(200)* %cap)
  ret i64 %address
}

; Capability-Modification Instructions

declare i8 addrspace(200)* @llvm.cheri.cap.seal(i8 addrspace(200)*, i8 addrspace(200)*)
declare i8 addrspace(200)* @llvm.cheri.cap.unseal(i8 addrspace(200)*, i8 addrspace(200)*)
declare i8 addrspace(200)* @llvm.cheri.cap.perms.and.i64(i8 addrspace(200)*, i64)
declare i8 addrspace(200)* @llvm.cheri.cap.flags.set.i64(i8 addrspace(200)*, i64)
declare i8 addrspace(200)* @llvm.cheri.cap.offset.set.i64(i8 addrspace(200)*, i64)
declare i8 addrspace(200)* @llvm.cheri.cap.address.set.i64(i8 addrspace(200)*, i64)
declare i8 addrspace(200)* @llvm.cheri.cap.bounds.set.i64(i8 addrspace(200)*, i64)
declare i8 addrspace(200)* @llvm.cheri.cap.bounds.set.exact.i64(i8 addrspace(200)*, i64)
declare i8 addrspace(200)* @llvm.cheri.cap.tag.clear(i8 addrspace(200)*)
declare i8 addrspace(200)* @llvm.cheri.cap.build(i8 addrspace(200)*, i8 addrspace(200)*)
declare i8 addrspace(200)* @llvm.cheri.cap.type.copy(i8 addrspace(200)*, i8 addrspace(200)*)
declare i8 addrspace(200)* @llvm.cheri.cap.conditional.seal(i8 addrspace(200)*, i8 addrspace(200)*)
declare i8 addrspace(200)* @llvm.cheri.cap.seal.entry(i8 addrspace(200)*)

define i8 addrspace(200)* @seal(i8 addrspace(200)* %cap1, i8 addrspace(200)* %cap2) nounwind {
; PURECAP-LABEL: seal:
; PURECAP:       # %bb.0:
; PURECAP-NEXT:    cjr $c17
; PURECAP-NEXT:    cseal $c3, $c3, $c4
;
; HYBRID-LABEL: seal:
; HYBRID:       # %bb.0:
; HYBRID-NEXT:    jr $ra
; HYBRID-NEXT:    cseal $c3, $c3, $c4
  %sealed = call i8 addrspace(200)* @llvm.cheri.cap.seal(i8 addrspace(200)* %cap1, i8 addrspace(200)* %cap2)
  ret i8 addrspace(200)* %sealed
}

define i8 addrspace(200)* @unseal(i8 addrspace(200)* %cap1, i8 addrspace(200)* %cap2) nounwind {
; PURECAP-LABEL: unseal:
; PURECAP:       # %bb.0:
; PURECAP-NEXT:    cjr $c17
; PURECAP-NEXT:    cunseal $c3, $c3, $c4
;
; HYBRID-LABEL: unseal:
; HYBRID:       # %bb.0:
; HYBRID-NEXT:    jr $ra
; HYBRID-NEXT:    cunseal $c3, $c3, $c4
  %unsealed = call i8 addrspace(200)* @llvm.cheri.cap.unseal(i8 addrspace(200)* %cap1, i8 addrspace(200)* %cap2)
  ret i8 addrspace(200)* %unsealed
}

define i8 addrspace(200)* @perms_and(i8 addrspace(200)* %cap, i64 %perms) nounwind {
; PURECAP-LABEL: perms_and:
; PURECAP:       # %bb.0:
; PURECAP-NEXT:    cjr $c17
; PURECAP-NEXT:    candperm $c3, $c3, $4
;
; HYBRID-LABEL: perms_and:
; HYBRID:       # %bb.0:
; HYBRID-NEXT:    jr $ra
; HYBRID-NEXT:    candperm $c3, $c3, $4
  %newcap = call i8 addrspace(200)* @llvm.cheri.cap.perms.and.i64(i8 addrspace(200)* %cap, i64 %perms)
  ret i8 addrspace(200)* %newcap
}

define i8 addrspace(200)* @flags_set(i8 addrspace(200)* %cap, i64 %flags) nounwind {
; PURECAP-LABEL: flags_set:
; PURECAP:       # %bb.0:
; PURECAP-NEXT:    cjr $c17
; PURECAP-NEXT:    csetflags $c3, $c3, $4
;
; HYBRID-LABEL: flags_set:
; HYBRID:       # %bb.0:
; HYBRID-NEXT:    jr $ra
; HYBRID-NEXT:    csetflags $c3, $c3, $4
  %newcap = call i8 addrspace(200)* @llvm.cheri.cap.flags.set.i64(i8 addrspace(200)* %cap, i64 %flags)
  ret i8 addrspace(200)* %newcap
}

define i8 addrspace(200)* @offset_set(i8 addrspace(200)* %cap, i64 %offset) nounwind {
; PURECAP-LABEL: offset_set:
; PURECAP:       # %bb.0:
; PURECAP-NEXT:    cjr $c17
; PURECAP-NEXT:    csetoffset $c3, $c3, $4
;
; HYBRID-LABEL: offset_set:
; HYBRID:       # %bb.0:
; HYBRID-NEXT:    jr $ra
; HYBRID-NEXT:    csetoffset $c3, $c3, $4
  %newcap = call i8 addrspace(200)* @llvm.cheri.cap.offset.set.i64(i8 addrspace(200)* %cap, i64 %offset)
  ret i8 addrspace(200)* %newcap
}

define i8 addrspace(200)* @address_set(i8 addrspace(200)* %cap, i64 %address) nounwind {
; PURECAP-LABEL: address_set:
; PURECAP:       # %bb.0:
; PURECAP-NEXT:    cjr $c17
; PURECAP-NEXT:    csetaddr $c3, $c3, $4
;
; HYBRID-LABEL: address_set:
; HYBRID:       # %bb.0:
; HYBRID-NEXT:    jr $ra
; HYBRID-NEXT:    csetaddr $c3, $c3, $4
  %newcap = call i8 addrspace(200)* @llvm.cheri.cap.address.set.i64(i8 addrspace(200)* %cap, i64 %address)
  ret i8 addrspace(200)* %newcap
}

define i8 addrspace(200)* @bounds_set(i8 addrspace(200)* %cap, i64 %bounds) nounwind {
; PURECAP-LABEL: bounds_set:
; PURECAP:       # %bb.0:
; PURECAP-NEXT:    cjr $c17
; PURECAP-NEXT:    csetbounds $c3, $c3, $4
;
; HYBRID-LABEL: bounds_set:
; HYBRID:       # %bb.0:
; HYBRID-NEXT:    jr $ra
; HYBRID-NEXT:    csetbounds $c3, $c3, $4
  %newcap = call i8 addrspace(200)* @llvm.cheri.cap.bounds.set.i64(i8 addrspace(200)* %cap, i64 %bounds)
  ret i8 addrspace(200)* %newcap
}

define i8 addrspace(200)* @bounds_set_exact(i8 addrspace(200)* %cap, i64 %bounds) nounwind {
; PURECAP-LABEL: bounds_set_exact:
; PURECAP:       # %bb.0:
; PURECAP-NEXT:    cjr $c17
; PURECAP-NEXT:    csetboundsexact $c3, $c3, $4
;
; HYBRID-LABEL: bounds_set_exact:
; HYBRID:       # %bb.0:
; HYBRID-NEXT:    jr $ra
; HYBRID-NEXT:    csetboundsexact $c3, $c3, $4
  %newcap = call i8 addrspace(200)* @llvm.cheri.cap.bounds.set.exact.i64(i8 addrspace(200)* %cap, i64 %bounds)
  ret i8 addrspace(200)* %newcap
}

define i8 addrspace(200)* @bounds_set_immediate(i8 addrspace(200)* %cap) nounwind {
; PURECAP-LABEL: bounds_set_immediate:
; PURECAP:       # %bb.0:
; PURECAP-NEXT:    cjr $c17
; PURECAP-NEXT:    csetbounds $c3, $c3, 42
;
; HYBRID-LABEL: bounds_set_immediate:
; HYBRID:       # %bb.0:
; HYBRID-NEXT:    jr $ra
; HYBRID-NEXT:    csetbounds $c3, $c3, 42
  %newcap = call i8 addrspace(200)* @llvm.cheri.cap.bounds.set.i64(i8 addrspace(200)* %cap, i64 42)
  ret i8 addrspace(200)* %newcap
}

define i8 addrspace(200)* @tag_clear(i8 addrspace(200)* %cap) nounwind {
; PURECAP-LABEL: tag_clear:
; PURECAP:       # %bb.0:
; PURECAP-NEXT:    cjr $c17
; PURECAP-NEXT:    ccleartag $c3, $c3
;
; HYBRID-LABEL: tag_clear:
; HYBRID:       # %bb.0:
; HYBRID-NEXT:    jr $ra
; HYBRID-NEXT:    ccleartag $c3, $c3
  %untagged = call i8 addrspace(200)* @llvm.cheri.cap.tag.clear(i8 addrspace(200)* %cap)
  ret i8 addrspace(200)* %untagged
}

define i8 addrspace(200)* @build(i8 addrspace(200)* %cap1, i8 addrspace(200)* %cap2) nounwind {
; PURECAP-LABEL: build:
; PURECAP:       # %bb.0:
; PURECAP-NEXT:    cjr $c17
; PURECAP-NEXT:    cbuildcap $c3, $c3, $c4
;
; HYBRID-LABEL: build:
; HYBRID:       # %bb.0:
; HYBRID-NEXT:    jr $ra
; HYBRID-NEXT:    cbuildcap $c3, $c3, $c4
  %built = call i8 addrspace(200)* @llvm.cheri.cap.build(i8 addrspace(200)* %cap1, i8 addrspace(200)* %cap2)
  ret i8 addrspace(200)* %built
}

define i8 addrspace(200)* @type_copy(i8 addrspace(200)* %cap1, i8 addrspace(200)* %cap2) nounwind {
; PURECAP-LABEL: type_copy:
; PURECAP:       # %bb.0:
; PURECAP-NEXT:    cjr $c17
; PURECAP-NEXT:    ccopytype $c3, $c3, $c4
;
; HYBRID-LABEL: type_copy:
; HYBRID:       # %bb.0:
; HYBRID-NEXT:    jr $ra
; HYBRID-NEXT:    ccopytype $c3, $c3, $c4
  %newcap = call i8 addrspace(200)* @llvm.cheri.cap.type.copy(i8 addrspace(200)* %cap1, i8 addrspace(200)* %cap2)
  ret i8 addrspace(200)* %newcap
}

define i8 addrspace(200)* @conditional_seal(i8 addrspace(200)* %cap1, i8 addrspace(200)* %cap2) nounwind {
; PURECAP-LABEL: conditional_seal:
; PURECAP:       # %bb.0:
; PURECAP-NEXT:    cjr $c17
; PURECAP-NEXT:    ccseal $c3, $c3, $c4
;
; HYBRID-LABEL: conditional_seal:
; HYBRID:       # %bb.0:
; HYBRID-NEXT:    jr $ra
; HYBRID-NEXT:    ccseal $c3, $c3, $c4
  %newcap = call i8 addrspace(200)* @llvm.cheri.cap.conditional.seal(i8 addrspace(200)* %cap1, i8 addrspace(200)* %cap2)
  ret i8 addrspace(200)* %newcap
}

define i8 addrspace(200)* @seal_entry(i8 addrspace(200)* %cap) nounwind {
; PURECAP-LABEL: seal_entry:
; PURECAP:       # %bb.0:
; PURECAP-NEXT:    cjr $c17
; PURECAP-NEXT:    csealentry $c3, $c3
;
; HYBRID-LABEL: seal_entry:
; HYBRID:       # %bb.0:
; HYBRID-NEXT:    jr $ra
; HYBRID-NEXT:    csealentry $c3, $c3
  %newcap = call i8 addrspace(200)* @llvm.cheri.cap.seal.entry(i8 addrspace(200)* %cap)
  ret i8 addrspace(200)* %newcap
}

; Pointer-Arithmetic Instructions

declare i64 @llvm.cheri.cap.to.pointer(i8 addrspace(200)*, i8 addrspace(200)*)
declare i8 addrspace(200)* @llvm.cheri.cap.from.pointer(i8 addrspace(200)*, i64)
declare i64 @llvm.cheri.cap.diff(i8 addrspace(200)*, i8 addrspace(200)*)
declare i8 addrspace(200)* @llvm.cheri.ddc.get()
declare i8 addrspace(200)* @llvm.cheri.pcc.get()

define i64 @to_pointer(i8 addrspace(200)* %cap1, i8 addrspace(200)* %cap2) nounwind {
; PURECAP-LABEL: to_pointer:
; PURECAP:       # %bb.0:
; PURECAP-NEXT:    cjr $c17
; PURECAP-NEXT:    ctoptr $2, $c4, $c3
;
; HYBRID-LABEL: to_pointer:
; HYBRID:       # %bb.0:
; HYBRID-NEXT:    jr $ra
; HYBRID-NEXT:    ctoptr $2, $c4, $c3
  %ptr = call i64 @llvm.cheri.cap.to.pointer(i8 addrspace(200)* %cap1, i8 addrspace(200)* %cap2)
  ret i64 %ptr
}

define i64 @to_pointer_ddc_relative(i8 addrspace(200)* %cap) nounwind {
; PURECAP-LABEL: to_pointer_ddc_relative:
; PURECAP:       # %bb.0:
; PURECAP-NEXT:    cjr $c17
; PURECAP-NEXT:    ctoptr $2, $c3, $ddc
;
; HYBRID-LABEL: to_pointer_ddc_relative:
; HYBRID:       # %bb.0:
; HYBRID-NEXT:    jr $ra
; HYBRID-NEXT:    ctoptr $2, $c3, $ddc
  %ddc = call i8 addrspace(200)* @llvm.cheri.ddc.get()
  %ptr = call i64 @llvm.cheri.cap.to.pointer(i8 addrspace(200)* %ddc, i8 addrspace(200)* %cap)
  ret i64 %ptr
}

define i8 addrspace(200)* @from_pointer(i8 addrspace(200)* %cap, i64 %ptr) nounwind {
; PURECAP-LABEL: from_pointer:
; PURECAP:       # %bb.0:
; PURECAP-NEXT:    cjr $c17
; PURECAP-NEXT:    cfromptr $c3, $c3, $4
;
; HYBRID-LABEL: from_pointer:
; HYBRID:       # %bb.0:
; HYBRID-NEXT:    jr $ra
; HYBRID-NEXT:    cfromptr $c3, $c3, $4
  %newcap = call i8 addrspace(200)* @llvm.cheri.cap.from.pointer(i8 addrspace(200)* %cap, i64 %ptr)
  ret i8 addrspace(200)* %newcap
}

define i8 addrspace(200)* @from_ddc(i64 %ptr) nounwind {
; PURECAP-LABEL: from_ddc:
; PURECAP:       # %bb.0:
; PURECAP-NEXT:    cjr $c17
; PURECAP-NEXT:    cfromddc $c3, $4
;
; HYBRID-LABEL: from_ddc:
; HYBRID:       # %bb.0:
; HYBRID-NEXT:    jr $ra
; HYBRID-NEXT:    cfromddc $c3, $4
  %ddc = call i8 addrspace(200)* @llvm.cheri.ddc.get()
  %cap = call i8 addrspace(200)* @llvm.cheri.cap.from.pointer(i8 addrspace(200)* %ddc, i64 %ptr)
  ret i8 addrspace(200)* %cap
}

define i64 @diff(i8 addrspace(200)* %cap1, i8 addrspace(200)* %cap2) nounwind {
; PURECAP-LABEL: diff:
; PURECAP:       # %bb.0:
; PURECAP-NEXT:    cjr $c17
; PURECAP-NEXT:    csub $2, $c3, $c4
;
; HYBRID-LABEL: diff:
; HYBRID:       # %bb.0:
; HYBRID-NEXT:    jr $ra
; HYBRID-NEXT:    csub $2, $c3, $c4
  %diff = call i64 @llvm.cheri.cap.diff(i8 addrspace(200)* %cap1, i8 addrspace(200)* %cap2)
  ret i64 %diff
}

define i8 addrspace(200)* @ddc_get() nounwind {
; PURECAP-LABEL: ddc_get:
; PURECAP:       # %bb.0:
; PURECAP-NEXT:    cjr $c17
; PURECAP-NEXT:    creadhwr $c3, $chwr_ddc
;
; HYBRID-LABEL: ddc_get:
; HYBRID:       # %bb.0:
; HYBRID-NEXT:    jr $ra
; HYBRID-NEXT:    creadhwr $c3, $chwr_ddc
  %cap = call i8 addrspace(200)* @llvm.cheri.ddc.get()
  ret i8 addrspace(200)* %cap
}

define i8 addrspace(200)* @pcc_get() nounwind {
; PURECAP-LABEL: pcc_get:
; PURECAP:       # %bb.0:
; PURECAP-NEXT:    cjr $c17
; PURECAP-NEXT:    cgetpcc $c3
;
; HYBRID-LABEL: pcc_get:
; HYBRID:       # %bb.0:
; HYBRID-NEXT:    jr $ra
; HYBRID-NEXT:    cgetpcc $c3
  %cap = call i8 addrspace(200)* @llvm.cheri.pcc.get()
  ret i8 addrspace(200)* %cap
}

; Assertion Instructions

declare i1 @llvm.cheri.cap.subset.test(i8 addrspace(200)* %cap1, i8 addrspace(200)* %cap2)

define i64 @subset_test(i8 addrspace(200)* %cap1, i8 addrspace(200)* %cap2) nounwind {
; PURECAP-LABEL: subset_test:
; PURECAP:       # %bb.0:
; PURECAP-NEXT:    cjr $c17
; PURECAP-NEXT:    ctestsubset $2, $c3, $c4
;
; HYBRID-LABEL: subset_test:
; HYBRID:       # %bb.0:
; HYBRID-NEXT:    jr $ra
; HYBRID-NEXT:    ctestsubset $2, $c3, $c4
  %subset = call i1 @llvm.cheri.cap.subset.test(i8 addrspace(200)* %cap1, i8 addrspace(200)* %cap2)
  %subset.zext = zext i1 %subset to i64
  ret i64 %subset.zext
}
