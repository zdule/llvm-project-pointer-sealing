// RUN: %cheri_purecap_cc1 -std=c2x %s -emit-llvm -o - | FileCheck %s
// RUN: %cheri_purecap_cc1 -std=c2x %s -emit-llvm -o - | bash -c "cat; false"

#include <stddef.h>

// CHECK-LABEL: define void @implicit_cast_from_unsealed
// CHECK: [[INCAP:%.*]] = bitcast i32 addrspace(200)* %{{.*}} to i8 addrspace(200)*
// CHECK: [[SEALCAP:%.*]] = load i8 addrspace(200)*, i8 addrspace(200)* addrspace(200)* @__cheri_sealing_capability, align 16
// CHECK: [[OFFSETSEAL:%.*]] = call i8 addrspace(200)* @llvm.cheri.cap.offset.set.i64(i8 addrspace(200)* [[SEALCAP]], i64 123)
// CHECK: [[SEALEDCAP:%.*]] = call i8 addrspace(200)* @llvm.cheri.cap.seal(i8 addrspace(200)* [[INCAP]], i8 addrspace(200)* [[OFFSETSEAL]])
// CHECK: [[OUTCAP:%.*]] = bitcast i8 addrspace(200)* [[SEALEDCAP]] to i32 addrspace(200)*
// CHECK: ret void

void implicit_cast_from_unsealed(int *p)
{
  int *[[cheri::sealed_pointer]] sp = p;
}

// CHECK-LABEL: define void @implicit_cast_to_unsealed
// CHECK: [[INCAP:%.*]] = bitcast i32 addrspace(200)* {{%.*}} to i8 addrspace(200)*
// CHECK: [[SEALCAP:%.*]] = load i8 addrspace(200)*, i8 addrspace(200)* addrspace(200)* @__cheri_sealing_capability, align 16
// CHECK: [[OFFSETSEAL:%.*]] = call i8 addrspace(200)* @llvm.cheri.cap.offset.set.i64(i8 addrspace(200)* [[SEALCAP]], i64 123)
// CHECK: [[UNSEALEDCAP:%.*]] = call i8 addrspace(200)* @llvm.cheri.cap.unseal(i8 addrspace(200)* [[INCAP]], i8 addrspace(200)* [[OFFSETSEAL]])
// CHECK: [[OUTCAP:%.*]] = bitcast i8 addrspace(200)* [[UNSEALEDCAP]] to i32 addrspace(200)*
void implicit_cast_to_unsealed(int *[[cheri::sealed_pointer]] sp)
{
  int *p = sp;
}

// CHECK-LABEL: define void @implicit_cast_from_NULL
// CHECK: @llvm.cheri.cap.seal
void implicit_cast_from_NULL()
{
  int *[[cheri::sealed_pointer]] sp = NULL;
}
