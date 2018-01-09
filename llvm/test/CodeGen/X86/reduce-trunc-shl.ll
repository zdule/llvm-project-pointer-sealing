; NOTE: Assertions have been autogenerated by utils/update_llc_test_checks.py
; RUN: llc < %s -mtriple=x86_64-unknown-linux-gnu -mattr=+sse2 | FileCheck %s --check-prefix=SSE2
; RUN: llc < %s -mtriple=x86_64-unknown-linux-gnu -mattr=+avx2 | FileCheck %s --check-prefix=AVX2

define void @trunc_shl_7_v4i32_v4i64(<4 x i32> addrspace(1)* %out, <4 x i64> addrspace(1)* %in) {
; SSE2-LABEL: trunc_shl_7_v4i32_v4i64:
; SSE2:       # BB#0:
; SSE2-NEXT:    movaps (%rsi), %xmm0
; SSE2-NEXT:    shufps {{.*#+}} xmm0 = xmm0[0,2],mem[0,2]
; SSE2-NEXT:    pslld $7, %xmm0
; SSE2-NEXT:    movdqa %xmm0, (%rdi)
; SSE2-NEXT:    retq
;
; AVX2-LABEL: trunc_shl_7_v4i32_v4i64:
; AVX2:       # BB#0:
; AVX2-NEXT:    vpshufd {{.*#+}} ymm0 = mem[0,2,2,3,4,6,6,7]
; AVX2-NEXT:    vpermq {{.*#+}} ymm0 = ymm0[0,2,2,3]
; AVX2-NEXT:    vpslld $7, %xmm0, %xmm0
; AVX2-NEXT:    vmovdqa %xmm0, (%rdi)
; AVX2-NEXT:    vzeroupper
; AVX2-NEXT:    retq
  %val = load <4 x i64>, <4 x i64> addrspace(1)* %in
  %shl = shl <4 x i64> %val, <i64 7, i64 7, i64 7, i64 7>
  %trunc = trunc <4 x i64> %shl to <4 x i32>
  store <4 x i32> %trunc, <4 x i32> addrspace(1)* %out
  ret void
}

define <8 x i16> @trunc_shl_v8i16_v8i32(<8 x i32> %a) {
; SSE2-LABEL: trunc_shl_v8i16_v8i32:
; SSE2:       # BB#0:
; SSE2-NEXT:    pslld $17, %xmm0
; SSE2-NEXT:    pslld $17, %xmm1
; SSE2-NEXT:    pslld $16, %xmm1
; SSE2-NEXT:    psrad $16, %xmm1
; SSE2-NEXT:    pslld $16, %xmm0
; SSE2-NEXT:    psrad $16, %xmm0
; SSE2-NEXT:    packssdw %xmm1, %xmm0
; SSE2-NEXT:    retq
;
; AVX2-LABEL: trunc_shl_v8i16_v8i32:
; AVX2:       # BB#0:
; AVX2-NEXT:    vpslld $17, %ymm0, %ymm0
; AVX2-NEXT:    vpshufb {{.*#+}} ymm0 = ymm0[0,1,4,5,8,9,12,13,8,9,12,13,12,13,14,15,16,17,20,21,24,25,28,29,24,25,28,29,28,29,30,31]
; AVX2-NEXT:    vpermq {{.*#+}} ymm0 = ymm0[0,2,2,3]
; AVX2-NEXT:    # kill: %xmm0<def> %xmm0<kill> %ymm0<kill>
; AVX2-NEXT:    vzeroupper
; AVX2-NEXT:    retq
  %shl = shl <8 x i32> %a, <i32 17, i32 17, i32 17, i32 17, i32 17, i32 17, i32 17, i32 17>
  %conv = trunc <8 x i32> %shl to <8 x i16>
  ret <8 x i16> %conv
}

define void @trunc_shl_31_i32_i64(i32* %out, i64* %in) {
; SSE2-LABEL: trunc_shl_31_i32_i64:
; SSE2:       # BB#0:
; SSE2-NEXT:    movl (%rsi), %eax
; SSE2-NEXT:    shll $31, %eax
; SSE2-NEXT:    movl %eax, (%rdi)
; SSE2-NEXT:    retq
;
; AVX2-LABEL: trunc_shl_31_i32_i64:
; AVX2:       # BB#0:
; AVX2-NEXT:    movl (%rsi), %eax
; AVX2-NEXT:    shll $31, %eax
; AVX2-NEXT:    movl %eax, (%rdi)
; AVX2-NEXT:    retq
  %val = load i64, i64* %in
  %shl = shl i64 %val, 31
  %trunc = trunc i64 %shl to i32
  store i32 %trunc, i32* %out
  ret void
}

define void @trunc_shl_32_i32_i64(i32* %out, i64* %in) {
; SSE2-LABEL: trunc_shl_32_i32_i64:
; SSE2:       # BB#0:
; SSE2-NEXT:    movl $0, (%rdi)
; SSE2-NEXT:    retq
;
; AVX2-LABEL: trunc_shl_32_i32_i64:
; AVX2:       # BB#0:
; AVX2-NEXT:    movl $0, (%rdi)
; AVX2-NEXT:    retq
  %val = load i64, i64* %in
  %shl = shl i64 %val, 32
  %trunc = trunc i64 %shl to i32
  store i32 %trunc, i32* %out
  ret void
}

define void @trunc_shl_15_i16_i64(i16* %out, i64* %in) {
; SSE2-LABEL: trunc_shl_15_i16_i64:
; SSE2:       # BB#0:
; SSE2-NEXT:    movzwl (%rsi), %eax
; SSE2-NEXT:    shlw $15, %ax
; SSE2-NEXT:    movw %ax, (%rdi)
; SSE2-NEXT:    retq
;
; AVX2-LABEL: trunc_shl_15_i16_i64:
; AVX2:       # BB#0:
; AVX2-NEXT:    movzwl (%rsi), %eax
; AVX2-NEXT:    shlw $15, %ax
; AVX2-NEXT:    movw %ax, (%rdi)
; AVX2-NEXT:    retq
  %val = load i64, i64* %in
  %shl = shl i64 %val, 15
  %trunc = trunc i64 %shl to i16
  store i16 %trunc, i16* %out
  ret void
}

define void @trunc_shl_16_i16_i64(i16* %out, i64* %in) {
; SSE2-LABEL: trunc_shl_16_i16_i64:
; SSE2:       # BB#0:
; SSE2-NEXT:    movw $0, (%rdi)
; SSE2-NEXT:    retq
;
; AVX2-LABEL: trunc_shl_16_i16_i64:
; AVX2:       # BB#0:
; AVX2-NEXT:    movw $0, (%rdi)
; AVX2-NEXT:    retq
  %val = load i64, i64* %in
  %shl = shl i64 %val, 16
  %trunc = trunc i64 %shl to i16
  store i16 %trunc, i16* %out
  ret void
}

define void @trunc_shl_7_i8_i64(i8* %out, i64* %in) {
; SSE2-LABEL: trunc_shl_7_i8_i64:
; SSE2:       # BB#0:
; SSE2-NEXT:    movb (%rsi), %al
; SSE2-NEXT:    shlb $7, %al
; SSE2-NEXT:    movb %al, (%rdi)
; SSE2-NEXT:    retq
;
; AVX2-LABEL: trunc_shl_7_i8_i64:
; AVX2:       # BB#0:
; AVX2-NEXT:    movb (%rsi), %al
; AVX2-NEXT:    shlb $7, %al
; AVX2-NEXT:    movb %al, (%rdi)
; AVX2-NEXT:    retq
  %val = load i64, i64* %in
  %shl = shl i64 %val, 7
  %trunc = trunc i64 %shl to i8
  store i8 %trunc, i8* %out
  ret void
}

define void @trunc_shl_8_i8_i64(i8* %out, i64* %in) {
; SSE2-LABEL: trunc_shl_8_i8_i64:
; SSE2:       # BB#0:
; SSE2-NEXT:    movb $0, (%rdi)
; SSE2-NEXT:    retq
;
; AVX2-LABEL: trunc_shl_8_i8_i64:
; AVX2:       # BB#0:
; AVX2-NEXT:    movb $0, (%rdi)
; AVX2-NEXT:    retq
  %val = load i64, i64* %in
  %shl = shl i64 %val, 8
  %trunc = trunc i64 %shl to i8
  store i8 %trunc, i8* %out
  ret void
}
