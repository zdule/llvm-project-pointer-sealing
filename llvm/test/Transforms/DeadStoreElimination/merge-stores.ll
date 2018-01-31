; NOTE: Assertions have been autogenerated by utils/update_test_checks.py
; RUN: opt -dse -enable-dse-partial-store-merging -S < %s | FileCheck %s
target datalayout = "e-p:64:64:64-i1:8:8-i8:8:8-i16:16:16-i32:32:32-i64:64:64-f32:32:32-f64:64:64-v64:64:64-v128:128:128-a0:0:64-s0:64:64-f80:128:128-f128:128:128-n8:16:32:64"

define void @byte_by_byte_replacement(i32 *%ptr) {
; CHECK-LABEL: @byte_by_byte_replacement(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    store i32 202050057, i32* [[PTR:%.*]]
; CHECK-NEXT:    ret void
;
entry:
  ;; This store's value should be modified as it should be better to use one
  ;; larger store than several smaller ones.
  ;; store will turn into 0x0C0B0A09 == 202050057
  store i32 305419896, i32* %ptr  ; 0x12345678
  %bptr = bitcast i32* %ptr to i8*
  %bptr1 = getelementptr inbounds i8, i8* %bptr, i64 1
  %bptr2 = getelementptr inbounds i8, i8* %bptr, i64 2
  %bptr3 = getelementptr inbounds i8, i8* %bptr, i64 3

  ;; We should be able to merge these four stores with the i32 above
  ; value (and bytes) stored before  ; 0x12345678
  store i8 9, i8* %bptr              ;         09
  store i8 10, i8* %bptr1            ;       0A
  store i8 11, i8* %bptr2            ;     0B
  store i8 12, i8* %bptr3            ;   0C
  ;                                    0x0C0B0A09
  ret void
}

define void @word_replacement(i64 *%ptr) {
; CHECK-LABEL: @word_replacement(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    store i64 8106482645252179720, i64* [[PTR:%.*]]
; CHECK-NEXT:    ret void
;
entry:
  store i64 72623859790382856, i64* %ptr  ; 0x0102030405060708

  %wptr = bitcast i64* %ptr to i16*
  %wptr1 = getelementptr inbounds i16, i16* %wptr, i64 1
  %wptr2 = getelementptr inbounds i16, i16* %wptr, i64 2
  %wptr3 = getelementptr inbounds i16, i16* %wptr, i64 3

  ;; We should be able to merge these two stores with the i64 one above
  ; value (not bytes) stored before  ; 0x0102030405060708
  store i16  4128, i16* %wptr1       ;           1020
  store i16 28800, i16* %wptr3       ;   7080
  ;                                    0x7080030410200708
  ret void
}


define void @differently_sized_replacements(i64 *%ptr) {
; CHECK-LABEL: @differently_sized_replacements(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    store i64 578437695752307201, i64* [[PTR:%.*]]
; CHECK-NEXT:    ret void
;
entry:
  store i64 579005069656919567, i64* %ptr  ; 0x08090a0b0c0d0e0f

  %bptr = bitcast i64* %ptr to i8*
  %bptr6 = getelementptr inbounds i8, i8* %bptr, i64 6
  %wptr = bitcast i64* %ptr to i16*
  %wptr2 = getelementptr inbounds i16, i16* %wptr, i64 2
  %dptr = bitcast i64* %ptr to i32*

  ;; We should be able to merge all these stores with the i64 one above
  ; value (not bytes) stored before  ; 0x08090a0b0c0d0e0f
  store i8         7, i8*  %bptr6    ;     07
  store i16     1541, i16* %wptr2    ;       0605
  store i32 67305985, i32* %dptr     ;           04030201
  ;                                    0x0807060504030201
  ret void
}


define void @multiple_replacements_to_same_byte(i64 *%ptr) {
; CHECK-LABEL: @multiple_replacements_to_same_byte(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    store i64 579005069522043393, i64* [[PTR:%.*]]
; CHECK-NEXT:    ret void
;
entry:
  store i64 579005069656919567, i64* %ptr  ; 0x08090a0b0c0d0e0f

  %bptr = bitcast i64* %ptr to i8*
  %bptr3 = getelementptr inbounds i8, i8* %bptr, i64 3
  %wptr = bitcast i64* %ptr to i16*
  %wptr1 = getelementptr inbounds i16, i16* %wptr, i64 1
  %dptr = bitcast i64* %ptr to i32*

  ;; We should be able to merge all these stores with the i64 one above
  ; value (not bytes) stored before  ; 0x08090a0b0c0d0e0f
  store i8         7, i8*  %bptr3    ;           07
  store i16     1541, i16* %wptr1    ;           0605
  store i32 67305985, i32* %dptr     ;           04030201
  ;                                    0x08090a0b04030201
  ret void
}

define void @merged_merges(i64 *%ptr) {
; CHECK-LABEL: @merged_merges(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    store i64 579005069572506113, i64* [[PTR:%.*]]
; CHECK-NEXT:    ret void
;
entry:
  store i64 579005069656919567, i64* %ptr  ; 0x08090a0b0c0d0e0f

  %bptr = bitcast i64* %ptr to i8*
  %bptr3 = getelementptr inbounds i8, i8* %bptr, i64 3
  %wptr = bitcast i64* %ptr to i16*
  %wptr1 = getelementptr inbounds i16, i16* %wptr, i64 1
  %dptr = bitcast i64* %ptr to i32*

  ;; We should be able to merge all these stores with the i64 one above
  ; value (not bytes) stored before  ; 0x08090a0b0c0d0e0f
  store i32 67305985, i32* %dptr     ;           04030201
  store i16     1541, i16* %wptr1    ;           0605
  store i8         7, i8*  %bptr3    ;           07
  ;                                    0x08090a0b07050201
  ret void
}

define signext i8 @shouldnt_merge_since_theres_a_full_overlap(i64 *%ptr) {
; CHECK-LABEL: @shouldnt_merge_since_theres_a_full_overlap(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[BPTR:%.*]] = bitcast i64* [[PTR:%.*]] to i8*
; CHECK-NEXT:    [[BPTRM1:%.*]] = getelementptr inbounds i8, i8* [[BPTR]], i64 -1
; CHECK-NEXT:    [[BPTR3:%.*]] = getelementptr inbounds i8, i8* [[BPTR]], i64 3
; CHECK-NEXT:    [[DPTR:%.*]] = bitcast i8* [[BPTRM1]] to i32*
; CHECK-NEXT:    [[QPTR:%.*]] = bitcast i8* [[BPTR3]] to i64*
; CHECK-NEXT:    store i32 1234, i32* [[DPTR]], align 1
; CHECK-NEXT:    store i64 5678, i64* [[QPTR]], align 1
; CHECK-NEXT:    ret i8 0
;
entry:

  ; Also check that alias.scope metadata doesn't get dropped
  store i64 0, i64* %ptr, !alias.scope !32

  %bptr = bitcast i64* %ptr to i8*
  %bptrm1 = getelementptr inbounds i8, i8* %bptr, i64 -1
  %bptr3 = getelementptr inbounds i8, i8* %bptr, i64 3
  %dptr = bitcast i8* %bptrm1 to i32*
  %qptr = bitcast i8* %bptr3 to i64*

  store i32 1234, i32* %dptr, align 1
  store i64 5678, i64* %qptr, align 1

  ret i8 0
}

;; Test case from PR31777
%union.U = type { i64 }

define void @foo(%union.U* nocapture %u) {
; CHECK-LABEL: @foo(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[I:%.*]] = getelementptr inbounds [[UNION_U:%.*]], %union.U* [[U:%.*]], i64 0, i32 0
; CHECK-NEXT:    store i64 42, i64* [[I]], align 8
; CHECK-NEXT:    ret void
;
entry:
  %i = getelementptr inbounds %union.U, %union.U* %u, i64 0, i32 0
  store i64 0, i64* %i, align 8, !dbg !22, !tbaa !26, !noalias !30, !nontemporal !29
  %s = bitcast %union.U* %u to i16*
  store i16 42, i16* %s, align 8
  ret void
}

; Don't crash by operating on stale data if we merge (kill) the last 2 stores.

define void @PR34074(i32* %x, i64* %y) {
; CHECK-LABEL: @PR34074(
; CHECK-NEXT:    store i64 42, i64* %y
; CHECK-NEXT:    store i32 4, i32* %x
; CHECK-NEXT:    ret void
;
  store i64 42, i64* %y          ; independent store
  %xbc = bitcast i32* %x to i8*
  store i32 0, i32* %x           ; big store of constant
  store i8 4, i8* %xbc           ; small store with mergeable constant
  ret void
}

; FIXME: We can't eliminate the last store because P and Q may alias.

define void @PR36129(i32* %P, i32* %Q) {
; CHECK-LABEL: @PR36129(
; CHECK-NEXT:    store i32 3, i32* [[P:%.*]]
; CHECK-NEXT:    store i32 2, i32* [[Q:%.*]]
; CHECK-NEXT:    ret void
;
  store i32 1, i32* %P
  %P2 = bitcast i32* %P to i8*
  store i32 2, i32* %Q
  store i8 3, i8* %P2
  ret void
}

!0 = distinct !DICompileUnit(language: DW_LANG_C_plus_plus, file: !1, producer: "clang version 5.0.0 (trunk 306512)", isOptimized: true, runtimeVersion: 0, emissionKind: FullDebug, enums: !2)
!1 = !DIFile(filename: "me.cpp", directory: "/compiler-explorer")
!2 = !{}
!7 = distinct !DISubprogram(name: "foo", linkageName: "foo(U*)", scope: !1, file: !1, line: 9, type: !8, isLocal: false, isDefinition: true, scopeLine: 9, flags: DIFlagPrototyped, isOptimized: true, unit: !0, variables: !20)
!8 = !DISubroutineType(types: !9)
!9 = !{null, !10}
!10 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !11, size: 64)
!11 = distinct !DICompositeType(tag: DW_TAG_union_type, name: "U", file: !1, line: 4, size: 64, elements: !12, identifier: "typeinfo name for U")
!12 = !{!13, !17}
!13 = !DIDerivedType(tag: DW_TAG_member, name: "i", scope: !11, file: !1, line: 5, baseType: !14, size: 64)
!14 = !DIDerivedType(tag: DW_TAG_typedef, name: "uint64_t", file: !15, line: 55, baseType: !16)
!15 = !DIFile(filename: "/usr/include/stdint.h", directory: "/compiler-explorer")
!16 = !DIBasicType(name: "long unsigned int", size: 64, encoding: DW_ATE_unsigned)
!17 = !DIDerivedType(tag: DW_TAG_member, name: "s", scope: !11, file: !1, line: 6, baseType: !18, size: 16)
!18 = !DIDerivedType(tag: DW_TAG_typedef, name: "uint16_t", file: !15, line: 49, baseType: !19)
!19 = !DIBasicType(name: "unsigned short", size: 16, encoding: DW_ATE_unsigned)
!20 = !{!21}
!21 = !DILocalVariable(name: "u", arg: 1, scope: !7, file: !1, line: 9, type: !10)
!22 = !DILocation(line: 10, column: 8, scope: !7)

!26 = !{!27, !27, i64 0}
!27 = !{!"omnipotent char", !28, i64 0}
!28 = !{!"Simple C++ TBAA"}

!29 = !{i32 1}

; Domains and scopes which might alias
!30 = !{!30}
!31 = !{!31, !30}

!32 = !{!32}
!33 = !{!33, !32}
