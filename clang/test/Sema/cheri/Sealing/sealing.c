// RUN: %cheri_purecap_cc1 -std=c2x %s -verify
// RUN: %cheri_purecap_cc1 -std=c2x %s -verify -ast-dump -o - | FileCheck %s
// RUN: %cheri_purecap_cc1 -std=c2x %s -verify -ast-dump -o - | bash -c "cat; false"
#include <stddef.h>

// CHECK-LABEL: |-FunctionDecl 0x{{.*}} dynamics 'int (void)'
int dynamics(void)
{
#pragma pointer_sealing sealed
  int x = 0;
  // CHECK: -VarDecl {{.*}} p 'int * __cheri_sealed_pointer'
  // CHECK-NEXT: -ImplicitCastExpr {{.*}} 'int * __cheri_sealed_pointer' <CHERISealedCapabilityConversion>
  int *p = &x;
  // CHECK: -BinaryOperator {{.*}} 'int' '='
  // CHECK-NEXT: -UnaryOperator {{.*}} '*'
  // CHECK-NEXT: -ImplicitCastExpr {{.*}} 'int *' <CHERISealedCapabilityConversion>
  // CHECK-NEXT: -ImplicitCastExpr {{.*}} 'int * __cheri_sealed_pointer' <LValueToRValue>
  *p = 1;
#pragma pointer_sealing unsealed

  typedef int *[[cheri::sealed_pointer]] PSI;
  typedef int * PI;
  PSI *ppsi = NULL;
  PI *ppi = NULL;
  ppi = ppsi; // expected-error {{converting capability  type}}
  ppsi = ppi; // expected-error {{converting capability  type}}
  return x;
}

// CHECK-LABEL: |-FunctionDecl 0x{{.*}} expressions 'void (void)'
void expressions(void)
{
  int x[10];
  // CHECK: -VarDecl {{.*}} p 'int * __cheri_sealed_pointer'
  // CHECK-NEXT: -ImplicitCastExpr {{.*}} 'int * __cheri_sealed_pointer' <CHERISealedCapabilityConversion>
  int *[[cheri::sealed_pointer]] p = x;

  // CHECK: -BinaryOperator {{.*}} '='
  // CHECK-NEXT: -DeclRefExpr
  // CHECK-NEXT: -ImplicitCastExpr {{.*}} 'int * __cheri_sealed_pointer' <CHERISealedCapabilityConversion>
  // CHECK-NEXT: -BinaryOperator {{.*}} '+'
  // CHECK-NEXT: -ImplicitCastExpr {{.*}} 'int *' <CHERISealedCapabilityConversion>
  p = p + 1;

  int *[[cheri::sealed_pointer]] q = p - 1;
  int *r = x;

  // CHECK: -VarDecl {{.*}} d 'ptrdiff_t'
  // CHECK-NEXT: -BinaryOperator {{.*}} '-'
  // CHECK: -ImplicitCastExpr {{.*}} 'int *' <CHERISealedCapabilityConversion>
  // CHECK: -DeclRefExpr {{.*}} 'p'
  // CHECK: -ImplicitCastExpr {{.*}} 'int *' <CHERISealedCapabilityConversion>
  // CHECK: -DeclRefExpr {{.*}} 'q'
  ptrdiff_t d = p - q;

  // Note, these need special handling in codegen.
  p += 10;
  p -= 5;
  p++;
  ++p;
  p--;
  --p;

  (void) (p == q);
  (void) (p != q);
  (void) (p > q);
  (void) (p < q);
  (void) (p >= q);
  (void) (p <= q);

  // Note: assignment from NULL is a special case.
  // CHECK: -BinaryOperator {{.*}} '='
  // CHECK-NEXT: -DeclRefExpr {{.*}} 'p'
  // CHECK-NEXT: -ImplicitCastExpr {{.*}} 'int * __cheri_sealed_pointer' <CHERISealedCapabilityConversion>
  // CHECK-NEXT: -ImplicitCastExpr {{.*}} 'int *' <NullToPointer>
  p = NULL;

  p = ((p >= q) ? p : r);
  p = ((void) p,p);

  int a[3];
  int *px = a;

  (void)(1 ? a : px);
}

struct S
{
  int *[[cheri::sealed_pointer]] p, *p1;
  int * q;
#pragma pointer_sealing sealed
  int * r;
#pragma pointer_sealing unsealed
};

union U
{
  int *[[cheri::sealed_pointer]] p;
  int * q;
};

int x;
// CHECK-LABEL: |-FunctionDecl 0x{{.*}} structs 'void (void)'
void structs(void) {
  // initializations and assignment
  // CHECK: -VarDecl {{.*}} s 'struct S'
  // CHECK-NEXT: -InitListExpr
  // CHECK-NEXT: -ImplicitCastExpr {{.*}} 'int * __cheri_sealed_pointer' <CHERISealedCapabilityConversion>
  struct S s = {.p = &x, .p1 = &x, .q = &x, .r = &x};
  // CHECK: -CompoundLiteralExpr {{.*}} 'struct S'
  // CHECK-NEXT: -InitListExpr
  // CHECK-NEXT: -ImplicitCastExpr {{.*}} 'int * __cheri_sealed_pointer' <CHERISealedCapabilityConversion>
  s = (struct S){.p = &x, .p1 = &x, .q = &x, .r = &x};

  // use through a sealed capability
  struct S *[[cheri::sealed_pointer]] sp = &s;
  // CHECK: -BinaryOperator {{.*}} 'int * __cheri_sealed_pointer' '='
  // CHECK-NEXT: -MemberExpr
  // CHECK-NEXT: -ImplicitCastExpr {{.*}} 'struct S *' <CHERISealedCapabilityConversion>
  sp->p = &x;
}

// CHECK-LABEL: |-FunctionDecl 0x{{.*}} unions 'void (void)'
void unions(void) {
  // CHECK: -VarDecl {{.*}} u 'union U'
  // CHECK-NEXT: -InitListExpr
  // CHECK-NEXT: -ImplicitCastExpr {{.*}} 'int * __cheri_sealed_pointer' <CHERISealedCapabilityConversion>
  union U u = {.p = &x};
  union U u1 = {.q = &x};
  // CHECK: -CompoundLiteralExpr {{.*}} 'union U'
  // CHECK-NEXT: -InitListExpr
  // CHECK-NEXT: -ImplicitCastExpr {{.*}} 'int * __cheri_sealed_pointer' <CHERISealedCapabilityConversion>
  u = (union U){.p = &x};
  u = (union U){.q = &x};

  // CHECK: -BinaryOperator {{.*}} 'int * __cheri_sealed_pointer' '='
  // CHECK-NEXT: -MemberExpr
  // CHECK-NEXT: -DeclRefExpr
  // CHECK-NEXT: -ImplicitCastExpr {{.*}} 'int * __cheri_sealed_pointer' <CHERISealedCapabilityConversion>
  u.p = &x;
  u.q = &x;

  union U *[[cheri::sealed_pointer]] up = &u;
  // CHECK: -BinaryOperator {{.*}} 'int * __cheri_sealed_pointer' '='
  // CHECK-NEXT: -MemberExpr
  // CHECK-NEXT: -ImplicitCastExpr {{.*}} 'union U *' <CHERISealedCapabilityConversion>
  up->p = &x;
}

// CHECK-LABEL: |-FunctionDecl 0x{{.*}} arrays 'void (void)'
void arrays(void) {
  // CHECK: -VarDecl {{.*}} a 'int * __cheri_sealed_pointer([2]
  // CHECK-NEXT: -InitListExpr
  // CHECK-NEXT: -ImplicitCastExpr {{.*}} 'int * __cheri_sealed_pointer'{{.*}} <CHERISealedCapabilityConversion>
  int *[[cheri::sealed_pointer]] (a[2]) = {&x, &x};

  // write to array elements
  // CHECK: -BinaryOperator {{.*}} 'int * __cheri_sealed_pointer'{{.*}} '='
  // CHECK: -ArraySubscriptExpr
  // CHECK: -ImplicitCastExpr {{.*}} 'int * __cheri_sealed_pointer'{{.*}} <CHERISealedCapabilityConversion>
  a[1] = &x;

  // CHECK: -VarDecl {{.*}} sa 'struct SA{{.*}}
  // CHECK-NEXT: -InitListExpr
  // CHECK-NEXT: -InitListExpr
  // CHECK-NEXT: -ImplicitCastExpr {{.*}} 'int * __cheri_sealed_pointer' <CHERISealedCapabilityConversion>
  struct SA {int *[[cheri::sealed_pointer]] a[2];} sa = {.a = {&x,&x}};
  sa = (struct SA) {.a = {&x, &x}};

  int *[[cheri::sealed_pointer]]((*[[cheri::sealed_pointer]]ap)[2]) = &a;
  // CHECK: -BinaryOperator {{.*}} 'int * __cheri_sealed_pointer'{{.*}} '='
  // CHECK-NEXT: -ArraySubscriptExpr
  // CHECK: -ImplicitCastExpr {{.*}} 'int * __cheri_sealed_pointer((*)[2])' <CHERISealedCapabilityConversion>
  (*ap)[1] = &x;
}

// CHECK-LABEL: |-FunctionDecl 0x{{.*}} f
int *[[cheri::sealed_pointer]] f(int *[[cheri::sealed_pointer]] p)
{
  return p;
}

typedef int *[[cheri::sealed_pointer]] (*FP)(int *[[cheri::sealed_pointer]] p);
typedef int *[[cheri::sealed_pointer]] (*[[cheri::sealed_pointer]] SFP)(int *[[cheri::sealed_pointer]] p);
typedef int *(*FP2)(int *[[cheri::sealed_pointer]] p);
typedef int *[[cheri::sealed_pointer]] (*FP3)(int *p);

// CHECK-LABEL: |-FunctionDecl 0x{{.*}} functions 'void (void)'
void functions(void)
{
  // should seal argument and unseal result
  // CHECK: -VarDecl {{.*}} p 'int *'
  // CHECK-NEXT: -ImplicitCastExpr {{.*}} 'int *' <CHERISealedCapabilityConversion>
  // CHECK-NEXT: -CallExpr
  // CHECK-NEXT: -ImplicitCastExpr {{.*}} <FunctionToPointerDecay>
  // CHECK-NEXT: -DeclRefExpr
  // CHECK-NEXT: -ImplicitCastExpr {{.*}} 'int * __cheri_sealed_pointer' <CHERISealedCapabilityConversion>
  int *p = f(&x);

  // can have sealed function pointers
  // CHECK: -VarDecl {{.*}} sfp 'SFP'
  // CHECK-NEXT: -ImplicitCastExpr {{.*}} 'SFP'{{.*}} <CHERISealedCapabilityConversion>
  SFP sfp = f;
  // CHECK: -VarDecl {{.*}} fp 'FP'
  // CHECK-NEXT: -ImplicitCastExpr {{.*}} 'FP'{{.*}} <CHERISealedCapabilityConversion>
  FP fp = sfp;

  //sealedness is a part of the function pointer type
  FP2 fp2 = f; // expected-warning {{incompatible function pointer types initializing}}
  FP3 fp3 = f; // expected-warning {{incompatible function pointer types initializing}}
}

void explicit_casts()
{
  int *[[cheri::sealed_pointer]] sp = (int *[[cheri::sealed_pointer]])&x;
  int *[[cheri::sealed_pointer]] nsp = (int *[[cheri::sealed_pointer]]) NULL;
  int *p = (int*) sp;
}

