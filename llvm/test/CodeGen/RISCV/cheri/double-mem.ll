; NOTE: Assertions have been autogenerated by utils/update_llc_test_checks.py
; FIXME: The patterns for 64-bit foating-point on RV32 have not been added yet
; RUN: llc -mtriple=riscv32 -target-abi ilp32 -mattr=+xcheri,-cap-mode,-f,-d -verify-machineinstrs < %s \
; RUN:   | FileCheck -check-prefix=RV32IXCHERI-ILP32 %s
; RUNTODO: llc -mtriple=riscv32 -target-abi ilp32d -mattr=+xcheri,-cap-mode,+f,+d -verify-machineinstrs < %s \
; RUNTODO:   | FileCheck -check-prefix=RV32IXCHERI-ILP32D %s
; RUN: llc -mtriple=riscv64 -target-abi lp64 -mattr=+xcheri,-cap-mode,-f,-d -verify-machineinstrs < %s \
; RUN:   | FileCheck -check-prefix=RV64IXCHERI-LP64 %s
; RUN: llc -mtriple=riscv64 -target-abi lp64d -mattr=+xcheri,-cap-mode,+f,+d -verify-machineinstrs < %s \
; RUN:   | FileCheck -check-prefix=RV64IXCHERI-LP64D %s

define double @load_double_via_cap(double addrspace(200)* %a) nounwind {
; RV32IXCHERI-ILP32-LABEL: load_double_via_cap:
; RV32IXCHERI-ILP32:       # %bb.0:
; RV32IXCHERI-ILP32-NEXT:    lw.cap a2, (ca0)
; RV32IXCHERI-ILP32-NEXT:    cincoffset ca0, ca0, 4
; RV32IXCHERI-ILP32-NEXT:    lw.cap a1, (ca0)
; RV32IXCHERI-ILP32-NEXT:    mv a0, a2
; RV32IXCHERI-ILP32-NEXT:    ret
;
; RV64IXCHERI-LP64-LABEL: load_double_via_cap:
; RV64IXCHERI-LP64:       # %bb.0:
; RV64IXCHERI-LP64-NEXT:    ld.cap a0, (ca0)
; RV64IXCHERI-LP64-NEXT:    ret
;
; RV64IXCHERI-LP64D-LABEL: load_double_via_cap:
; RV64IXCHERI-LP64D:       # %bb.0:
; RV64IXCHERI-LP64D-NEXT:    ld.cap a0, (ca0)
; RV64IXCHERI-LP64D-NEXT:    fmv.d.x fa0, a0
; RV64IXCHERI-LP64D-NEXT:    ret
  %loaded = load double, double addrspace(200)* %a, align 8
  ret double %loaded
}

define void @store_double_via_cap(double addrspace(200)* %a, double %value) nounwind {
; RV32IXCHERI-ILP32-LABEL: store_double_via_cap:
; RV32IXCHERI-ILP32:       # %bb.0:
; RV32IXCHERI-ILP32-NEXT:    sw.cap a1, (ca0)
; RV32IXCHERI-ILP32-NEXT:    cincoffset ca0, ca0, 4
; RV32IXCHERI-ILP32-NEXT:    sw.cap a2, (ca0)
; RV32IXCHERI-ILP32-NEXT:    ret
;
; RV64IXCHERI-LP64-LABEL: store_double_via_cap:
; RV64IXCHERI-LP64:       # %bb.0:
; RV64IXCHERI-LP64-NEXT:    sd.cap a1, (ca0)
; RV64IXCHERI-LP64-NEXT:    ret
;
; RV64IXCHERI-LP64D-LABEL: store_double_via_cap:
; RV64IXCHERI-LP64D:       # %bb.0:
; RV64IXCHERI-LP64D-NEXT:    fmv.x.d a1, fa0
; RV64IXCHERI-LP64D-NEXT:    sd.cap a1, (ca0)
; RV64IXCHERI-LP64D-NEXT:    ret
  store double %value, double addrspace(200)* %a, align 8
  ret void
}
