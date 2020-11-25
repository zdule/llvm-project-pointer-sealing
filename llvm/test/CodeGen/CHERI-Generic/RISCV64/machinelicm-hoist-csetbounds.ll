; NOTE: Assertions have been autogenerated by utils/update_test_checks.py UTC_ARGS: --function-signature --scrub-attributes --force-update
; DO NOT EDIT -- This file was generated from test/CodeGen/CHERI-Generic/Inputs/machinelicm-hoist-csetbounds.ll
; Previously LLVM would hoist CSetBounds instructions out of if conditions/loops
; even if the source pointer could be NULL. On MIPS and RISC-V this results in a
; tag violation so we must ensure that the CSetBounds happens after the NULL check.

; Note: Opt correctly hoists the condition+csetbounds into a preheader, and LLC
; used to unconditionally hoist the csetbounds.
; RUN: opt -mtriple=riscv64 --relocation-model=pic -target-abi l64pc128d -mattr=+xcheri,+cap-mode,+f,+d -O3 -S < %s | FileCheck %s --check-prefix=HOIST-OPT
; RUN: llc -mtriple=riscv64 --relocation-model=pic -target-abi l64pc128d -mattr=+xcheri,+cap-mode,+f,+d -O3 < %s | FileCheck %s

; Generated from the following C code (with subobject bounds):
; struct foo {
;     int src;
;     int dst;
; };
;
; void call(int* src, int* dst);
;
; void hoist_csetbounds(int cond, struct foo* f) {
;     for (int i = 0; i < 100; i++) {
;         if (f) {
;             call(&f->src, &f->dst);
;         }
;     }
; }

%struct.foo = type { i32, i32 }
declare dso_local void @call(i32 addrspace(200)*, i32 addrspace(200)*) local_unnamed_addr addrspace(200) nounwind
declare i8 addrspace(200)* @llvm.cheri.cap.bounds.set.i64(i8 addrspace(200)*, i64) addrspace(200) nounwind readnone willreturn

define dso_local void @hoist_csetbounds(i32 signext %cond, %struct.foo addrspace(200)* %f) local_unnamed_addr addrspace(200) nounwind {
; CHECK-LABEL: hoist_csetbounds:
; CHECK:       # %bb.0: # %entry
; CHECK-NEXT:    cincoffset csp, csp, -96
; CHECK-NEXT:    csc cra, 80(csp)
; CHECK-NEXT:    csc cs0, 64(csp)
; CHECK-NEXT:    csc cs1, 48(csp)
; CHECK-NEXT:    csc cs2, 32(csp)
; CHECK-NEXT:    csc cs3, 16(csp)
; CHECK-NEXT:    csc cs4, 0(csp)
; CHECK-NEXT:    cmove cs2, ca1
; CHECK-NEXT:    mv s0, zero
; CHECK-NEXT:    seqz s1, s2
; CHECK-NEXT:    cincoffset cs3, ca1, 4
; CHECK-NEXT:    addi s4, zero, 99
; CHECK-NEXT:    j .LBB0_2
; CHECK-NEXT:  .LBB0_1: # %for.inc
; CHECK-NEXT:    # in Loop: Header=BB0_2 Depth=1
; CHECK-NEXT:    sext.w a0, s0
; CHECK-NEXT:    addi s0, s0, 1
; CHECK-NEXT:    bgeu a0, s4, .LBB0_4
; CHECK-NEXT:  .LBB0_2: # %for.body
; CHECK-NEXT:    # =>This Inner Loop Header: Depth=1
; CHECK-NEXT:    bnez s1, .LBB0_1
; CHECK-NEXT:  # %bb.3: # %if.then
; CHECK-NEXT:    # in Loop: Header=BB0_2 Depth=1
; CHECK-NEXT:    csetbounds ca0, cs2, 4
; CHECK-NEXT:    csetbounds ca1, cs3, 4
; CHECK-NEXT:  .LBB0_5: # %if.then
; CHECK-NEXT:    # in Loop: Header=BB0_2 Depth=1
; CHECK-NEXT:    # Label of block must be emitted
; CHECK-NEXT:    auipcc ca2, %captab_pcrel_hi(call)
; CHECK-NEXT:    clc ca2, %pcrel_lo(.LBB0_5)(ca2)
; CHECK-NEXT:    cjalr ca2
; CHECK-NEXT:    j .LBB0_1
; CHECK-NEXT:  .LBB0_4: # %for.cond.cleanup
; CHECK-NEXT:    clc cs4, 0(csp)
; CHECK-NEXT:    clc cs3, 16(csp)
; CHECK-NEXT:    clc cs2, 32(csp)
; CHECK-NEXT:    clc cs1, 48(csp)
; CHECK-NEXT:    clc cs0, 64(csp)
; CHECK-NEXT:    clc cra, 80(csp)
; CHECK-NEXT:    cincoffset csp, csp, 96
; CHECK-NEXT:    cret
; HOIST-OPT-LABEL: define {{[^@]+}}@hoist_csetbounds
; HOIST-OPT-SAME: (i32 signext [[COND:%.*]], [[STRUCT_FOO:%.*]] addrspace(200)* [[F:%.*]]) local_unnamed_addr addrspace(200) [[ATTR0:#.*]] {
; HOIST-OPT-NEXT:  entry:
; HOIST-OPT-NEXT:    [[TOBOOL:%.*]] = icmp eq [[STRUCT_FOO]] addrspace(200)* [[F]], null
; HOIST-OPT-NEXT:    br i1 [[TOBOOL]], label [[FOR_COND_CLEANUP:%.*]], label [[FOR_BODY_PREHEADER:%.*]]
; HOIST-OPT:       for.body.preheader:
; HOIST-OPT-NEXT:    [[DST:%.*]] = getelementptr inbounds [[STRUCT_FOO]], [[STRUCT_FOO]] addrspace(200)* [[F]], i64 0, i32 1
; HOIST-OPT-NEXT:    [[TMP0:%.*]] = bitcast i32 addrspace(200)* [[DST]] to i8 addrspace(200)*
; HOIST-OPT-NEXT:    [[TMP1:%.*]] = bitcast [[STRUCT_FOO]] addrspace(200)* [[F]] to i8 addrspace(200)*
; HOIST-OPT-NEXT:    [[TMP2:%.*]] = tail call addrspace(200) i8 addrspace(200)* @llvm.cheri.cap.bounds.set.i64(i8 addrspace(200)* nonnull [[TMP1]], i64 4)
; HOIST-OPT-NEXT:    [[ADDRESS_WITH_BOUNDS:%.*]] = bitcast i8 addrspace(200)* [[TMP2]] to i32 addrspace(200)*
; HOIST-OPT-NEXT:    [[TMP3:%.*]] = tail call addrspace(200) i8 addrspace(200)* @llvm.cheri.cap.bounds.set.i64(i8 addrspace(200)* nonnull [[TMP0]], i64 4)
; HOIST-OPT-NEXT:    [[ADDRESS_WITH_BOUNDS1:%.*]] = bitcast i8 addrspace(200)* [[TMP3]] to i32 addrspace(200)*
; HOIST-OPT-NEXT:    br label [[FOR_BODY:%.*]]
; HOIST-OPT:       for.cond.cleanup:
; HOIST-OPT-NEXT:    ret void
; HOIST-OPT:       for.body:
; HOIST-OPT-NEXT:    [[I_06:%.*]] = phi i32 [ [[INC:%.*]], [[FOR_BODY]] ], [ 0, [[FOR_BODY_PREHEADER]] ]
; HOIST-OPT-NEXT:    tail call addrspace(200) void @call(i32 addrspace(200)* [[ADDRESS_WITH_BOUNDS]], i32 addrspace(200)* [[ADDRESS_WITH_BOUNDS1]])
; HOIST-OPT-NEXT:    [[INC]] = add nuw nsw i32 [[I_06]], 1
; HOIST-OPT-NEXT:    [[CMP:%.*]] = icmp ult i32 [[I_06]], 99
; HOIST-OPT-NEXT:    br i1 [[CMP]], label [[FOR_BODY]], label [[FOR_COND_CLEANUP]]
;
entry:
  %tobool = icmp eq %struct.foo addrspace(200)* %f, null
  %0 = bitcast %struct.foo addrspace(200)* %f to i8 addrspace(200)*
  %dst = getelementptr inbounds %struct.foo, %struct.foo addrspace(200)* %f, i64 0, i32 1
  %1 = bitcast i32 addrspace(200)* %dst to i8 addrspace(200)*
  br label %for.body

for.cond.cleanup:                                 ; preds = %for.inc
  ret void

for.body:                                         ; preds = %entry, %for.inc
  %i.06 = phi i32 [ 0, %entry ], [ %inc, %for.inc ]
  br i1 %tobool, label %for.inc, label %if.then

if.then:                                          ; preds = %for.body
  %2 = call i8 addrspace(200)* @llvm.cheri.cap.bounds.set.i64(i8 addrspace(200)* nonnull %0, i64 4)
  %address.with.bounds = bitcast i8 addrspace(200)* %2 to i32 addrspace(200)*
  %3 = call i8 addrspace(200)* @llvm.cheri.cap.bounds.set.i64(i8 addrspace(200)* nonnull %1, i64 4)
  %address.with.bounds1 = bitcast i8 addrspace(200)* %3 to i32 addrspace(200)*
  call void @call(i32 addrspace(200)* %address.with.bounds, i32 addrspace(200)* %address.with.bounds1)
  br label %for.inc

for.inc:                                          ; preds = %for.body, %if.then
  %inc = add nuw nsw i32 %i.06, 1
  %cmp = icmp ult i32 %i.06, 99
  br i1 %cmp, label %for.body, label %for.cond.cleanup
}
