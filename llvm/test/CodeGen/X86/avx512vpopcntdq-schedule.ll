; NOTE: Assertions have been autogenerated by utils/update_llc_test_checks.py
; RUN: llc < %s -mtriple=x86_64-unknown-unknown -print-schedule -mcpu=x86-64 -mattr=+avx512vpopcntdq | FileCheck %s --check-prefix=GENERIC
; RUN: llc < %s -mtriple=x86_64-unknown-unknown -print-schedule -mcpu=icelake-client | FileCheck %s --check-prefix=ICELAKE
; RUN: llc < %s -mtriple=x86_64-unknown-unknown -print-schedule -mcpu=icelake-server | FileCheck %s --check-prefix=ICELAKE

define void @test_vpopcntd(<16 x i32> %a0, <16 x i32> %a1, <16 x i32> *%a2, i16 %a3) {
; GENERIC-LABEL: test_vpopcntd:
; GENERIC:       # %bb.0:
; GENERIC-NEXT:    kmovw %esi, %k1 # sched: [1:0.33]
; GENERIC-NEXT:    #APP
; GENERIC-NEXT:    vpopcntd %zmm1, %zmm0 # sched: [1:0.50]
; GENERIC-NEXT:    vpopcntd %zmm1, %zmm0 {%k1} # sched: [1:0.50]
; GENERIC-NEXT:    vpopcntd %zmm1, %zmm0 {%k1} {z} # sched: [1:0.50]
; GENERIC-NEXT:    vpopcntd (%rdi), %zmm0 # sched: [8:0.50]
; GENERIC-NEXT:    vpopcntd (%rdi), %zmm0 {%k1} # sched: [8:0.50]
; GENERIC-NEXT:    vpopcntd (%rdi), %zmm0 {%k1} {z} # sched: [8:0.50]
; GENERIC-NEXT:    vpopcntd (%rdi){1to16}, %zmm0 # sched: [8:0.50]
; GENERIC-NEXT:    vpopcntd (%rdi){1to16}, %zmm0 {%k1} # sched: [8:0.50]
; GENERIC-NEXT:    vpopcntd (%rdi){1to16}, %zmm0 {%k1} {z} # sched: [8:0.50]
; GENERIC-NEXT:    #NO_APP
; GENERIC-NEXT:    vzeroupper # sched: [100:0.33]
; GENERIC-NEXT:    retq # sched: [1:1.00]
;
; ICELAKE-LABEL: test_vpopcntd:
; ICELAKE:       # %bb.0:
; ICELAKE-NEXT:    kmovd %esi, %k1 # sched: [1:1.00]
; ICELAKE-NEXT:    #APP
; ICELAKE-NEXT:    vpopcntd %zmm1, %zmm0 # sched: [1:0.50]
; ICELAKE-NEXT:    vpopcntd %zmm1, %zmm0 {%k1} # sched: [1:0.50]
; ICELAKE-NEXT:    vpopcntd %zmm1, %zmm0 {%k1} {z} # sched: [1:0.50]
; ICELAKE-NEXT:    vpopcntd (%rdi), %zmm0 # sched: [8:0.50]
; ICELAKE-NEXT:    vpopcntd (%rdi), %zmm0 {%k1} # sched: [8:0.50]
; ICELAKE-NEXT:    vpopcntd (%rdi), %zmm0 {%k1} {z} # sched: [8:0.50]
; ICELAKE-NEXT:    vpopcntd (%rdi){1to16}, %zmm0 # sched: [8:0.50]
; ICELAKE-NEXT:    vpopcntd (%rdi){1to16}, %zmm0 {%k1} # sched: [8:0.50]
; ICELAKE-NEXT:    vpopcntd (%rdi){1to16}, %zmm0 {%k1} {z} # sched: [8:0.50]
; ICELAKE-NEXT:    #NO_APP
; ICELAKE-NEXT:    vzeroupper # sched: [4:1.00]
; ICELAKE-NEXT:    retq # sched: [7:1.00]
  tail call void asm "vpopcntd $1, $0 \0A\09 vpopcntd $1, $0 {$3} \0A\09 vpopcntd $1, $0 {$3} {z} \0A\09 vpopcntd $2, $0 \0A\09 vpopcntd $2, $0 {$3} \0A\09 vpopcntd $2, $0 {$3} {z} \0A\09 vpopcntd $2{1to16}, $0 \0A\09 vpopcntd $2{1to16}, $0 {$3} \0A\09 vpopcntd $2{1to16}, $0 {$3} {z}", "v,v,*m,^Yk"(<16 x i32> %a0, <16 x i32> %a1, <16 x i32> *%a2, i16 %a3) nounwind
  ret void
}

define void @test_vpopcntq(<8 x i64> %a0, <8 x i64> %a1, <8 x i64> *%a2, i8 %a3) {
; GENERIC-LABEL: test_vpopcntq:
; GENERIC:       # %bb.0:
; GENERIC-NEXT:    kmovw %esi, %k1 # sched: [1:0.33]
; GENERIC-NEXT:    #APP
; GENERIC-NEXT:    vpopcntq %zmm1, %zmm0 # sched: [1:0.50]
; GENERIC-NEXT:    vpopcntq %zmm1, %zmm0 {%k1} # sched: [1:0.50]
; GENERIC-NEXT:    vpopcntq %zmm1, %zmm0 {%k1} {z} # sched: [1:0.50]
; GENERIC-NEXT:    vpopcntq (%rdi), %zmm0 # sched: [8:0.50]
; GENERIC-NEXT:    vpopcntq (%rdi), %zmm0 {%k1} # sched: [8:0.50]
; GENERIC-NEXT:    vpopcntq (%rdi), %zmm0 {%k1} {z} # sched: [8:0.50]
; GENERIC-NEXT:    vpopcntq (%rdi){1to8}, %zmm0 # sched: [8:0.50]
; GENERIC-NEXT:    vpopcntq (%rdi){1to8}, %zmm0 {%k1} # sched: [8:0.50]
; GENERIC-NEXT:    vpopcntq (%rdi){1to8}, %zmm0 {%k1} {z} # sched: [8:0.50]
; GENERIC-NEXT:    #NO_APP
; GENERIC-NEXT:    vzeroupper # sched: [100:0.33]
; GENERIC-NEXT:    retq # sched: [1:1.00]
;
; ICELAKE-LABEL: test_vpopcntq:
; ICELAKE:       # %bb.0:
; ICELAKE-NEXT:    kmovd %esi, %k1 # sched: [1:1.00]
; ICELAKE-NEXT:    #APP
; ICELAKE-NEXT:    vpopcntq %zmm1, %zmm0 # sched: [1:0.50]
; ICELAKE-NEXT:    vpopcntq %zmm1, %zmm0 {%k1} # sched: [1:0.50]
; ICELAKE-NEXT:    vpopcntq %zmm1, %zmm0 {%k1} {z} # sched: [1:0.50]
; ICELAKE-NEXT:    vpopcntq (%rdi), %zmm0 # sched: [8:0.50]
; ICELAKE-NEXT:    vpopcntq (%rdi), %zmm0 {%k1} # sched: [8:0.50]
; ICELAKE-NEXT:    vpopcntq (%rdi), %zmm0 {%k1} {z} # sched: [8:0.50]
; ICELAKE-NEXT:    vpopcntq (%rdi){1to8}, %zmm0 # sched: [8:0.50]
; ICELAKE-NEXT:    vpopcntq (%rdi){1to8}, %zmm0 {%k1} # sched: [8:0.50]
; ICELAKE-NEXT:    vpopcntq (%rdi){1to8}, %zmm0 {%k1} {z} # sched: [8:0.50]
; ICELAKE-NEXT:    #NO_APP
; ICELAKE-NEXT:    vzeroupper # sched: [4:1.00]
; ICELAKE-NEXT:    retq # sched: [7:1.00]
  tail call void asm "vpopcntq $1, $0 \0A\09 vpopcntq $1, $0 {$3} \0A\09 vpopcntq $1, $0 {$3} {z} \0A\09 vpopcntq $2, $0 \0A\09 vpopcntq $2, $0 {$3} \0A\09 vpopcntq $2, $0 {$3} {z} \0A\09 vpopcntq $2{1to8}, $0 \0A\09 vpopcntq $2{1to8}, $0 {$3} \0A\09 vpopcntq $2{1to8}, $0 {$3} {z}", "v,v,*m,^Yk"(<8 x i64> %a0, <8 x i64> %a1, <8 x i64> *%a2, i8 %a3) nounwind
  ret void
}
