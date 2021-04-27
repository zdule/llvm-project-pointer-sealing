// RUN1: %cheri_purecap_cc1 -DSK=dynamic -std=c2x %s -emit-llvm -o - | bash -c "cat; false"
// RUN: %cheri_purecap_cc1 -DSK=syntactic -std=c2x %s -emit-llvm -o - | FileCheck %s --check-prefixes=CHECK,STATIC
// RUN: %cheri_purecap_cc1 -DSK=dynamic -std=c2x %s -emit-llvm -o - | FileCheck %s --check-prefixes=CHECK,DYNAM

#include <stddef.h>

#define SEALED [[cheri::sealed_pointer(SK)]]
#define UNSEALED [[cheri::sealed_pointer(unsealed)]]
#define trust(X) __builtin_cheri_trust_capability(X)
#pragma pointer_sealing SK

// CHECK-LABEL: define void @trust_capability
// STATIC: [[INCAP:%.*]] = bitcast i32 addrspace(200)* %{{.*}} to i8 addrspace(200)*
// STATIC: call void @__cheri_cast_check(i8 addrspace(200)* [[INCAP]],
// CHECK: [[SEALCAP:%.*]] = load i8 addrspace(200)*, i8 addrspace(200)* addrspace(200)* @__cheri_sealing_capability, align 16
// CHECK: [[INCAP:%.*]] = bitcast i32 addrspace(200)* %{{.*}} to i8 addrspace(200)*
// CHECK: [[OFFSETSEAL:%.*]] = call i8 addrspace(200)* @llvm.cheri.cap.offset.set.i64(i8 addrspace(200)* [[SEALCAP]],
// CHECK: [[SEALEDCAP:%.*]] = call i8 addrspace(200)* @llvm.cheri.cap.seal(i8 addrspace(200)* [[INCAP]], i8 addrspace(200)* [[OFFSETSEAL]])
// CHECK: [[OUTCAP:%.*]] = bitcast i8 addrspace(200)* [[SEALEDCAP]] to i32 addrspace(200)*
// CHECK: ret void

void trust_capability(int *UNSEALED p)
{
  int *SEALED sp = trust(p);
}

// CHECK-LABEL: define void @implicit_cast_to_unsealed
// CHECK: [[SEALCAP:%.*]] = load i8 addrspace(200)*, i8 addrspace(200)* addrspace(200)* @__cheri_sealing_capability, align 16
// DYNAM: [[SEALCAP:%.*]] = load i8 addrspace(200)*, i8 addrspace(200)* addrspace(200)* @__cheri_sealing_capability, align 16
// CHECK: [[INCAP:%.*]] = bitcast i32 addrspace(200)* {{%.*}} to i8 addrspace(200)*
// DYNAM: [[OTYPE:%.*]] = call i64 @llvm.cheri.cap.type.get.i64(i8 addrspace(200)* [[INCAP]])
// CHECK: [[OFFSETSEAL:%.*]] = call i8 addrspace(200)* @llvm.cheri.cap.offset.set.i64(i8 addrspace(200)* [[SEALCAP]],
// CHECK: [[UNSEALEDCAP:%.*]] = call i8 addrspace(200)* @llvm.cheri.cap.unseal(i8 addrspace(200)* [[INCAP]], i8 addrspace(200)* [[OFFSETSEAL]])
// CHECK: [[OUTCAP:%.*]] = bitcast i8 addrspace(200)* [[UNSEALEDCAP]] to i32 addrspace(200)*
void implicit_cast_to_unsealed(int *SEALED sp)
{
  int *UNSEALED p = sp;
}

// CHECK-LABEL: define void @implicit_cast_from_NULL
// CHECK: @llvm.cheri.cap.seal
void implicit_cast_from_NULL()
{
  int *SEALED sp = NULL;
}
