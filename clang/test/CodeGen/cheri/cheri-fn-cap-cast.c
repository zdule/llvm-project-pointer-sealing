// NOTE: Assertions have been autogenerated by utils/update_cc_test_checks.py
// RUN: %cheri_cc1 %s -emit-llvm  -o - | FileCheck %s
void (*__capability c)(void);
typedef void (*fnptr)(void);
// CHECK-LABEL: define {{[^@]+}}@cheri_codeptr
// CHECK-SAME: (void ()* [[PTR:%.*]]) #0
// CHECK-NEXT:  entry:
// CHECK-NEXT:    [[PTR_ADDR:%.*]] = alloca void ()*, align 8
// CHECK-NEXT:    store void ()* [[PTR]], void ()** [[PTR_ADDR]], align 8
// CHECK-NEXT:    [[TMP0:%.*]] = load void ()*, void ()** [[PTR_ADDR]], align 8
// CHECK-NEXT:    [[TMP1:%.*]] = call i8 addrspace(200)* @llvm.cheri.pcc.get()
// CHECK-NEXT:    [[TMP2:%.*]] = ptrtoint void ()* [[TMP0]] to i64
// CHECK-NEXT:    [[TMP3:%.*]] = call i8 addrspace(200)* @llvm.cheri.cap.from.pointer.i64(i8 addrspace(200)* [[TMP1]], i64 [[TMP2]])
// CHECK-NEXT:    [[TMP4:%.*]] = bitcast i8 addrspace(200)* [[TMP3]] to void () addrspace(200)*
// CHECK-NEXT:    store void () addrspace(200)* [[TMP4]], void () addrspace(200)** @c, align 16
// CHECK-NEXT:    ret void
//
void cheri_codeptr(const fnptr ptr) {
  // Check that this cast is PCC-relative and not DDC-relative
  c = (__cheri_tocap void (*__capability)(void))ptr;
}
