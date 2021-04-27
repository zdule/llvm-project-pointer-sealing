// RUN1: %cheri_purecap_cc1 -D SK=syntactic -std=c2x %s -verify
// RUN: %cheri_purecap_cc1 -D SK=syntactic -std=c2x %s -verify -ast-dump -o - | FileCheck --DSK=static --DStXU=StaticSealedToStaticUnsealedPointerCast --DXUtU=NoOp -DXUtS=StaticUnsealedToStaticSealedPointerCast %s
// RUN: %cheri_purecap_cc1 -D SK=dynamic -std=c2x %s -verify -ast-dump -o - | FileCheck --DSK=dynamic --DStXU=DynamicSealedToDynamicUnsealedPointerCast --DXUtU=DynamicUnsealedToUnsealedPointerCast -DXUtS=DynamicUnsealedToDynamicSealedPointerCast %s
// RUN1: %cheri_purecap_cc1 -std=c2x %s -verify -ast-dump -o - | bash -c "cat; false"
#include <stddef.h>
//#define SK syntactic
#define SEALED [[cheri::sealed_pointer(SK)]]
#define UNSEALED [[cheri::sealed_pointer(unsealed)]]

#pragma pointer_sealing SK
// CHECK-LABEL: |-FunctionDecl 0x{{.*}} dynamics 'int (void)'
int dynamics(void)
{
  int x = 0;
  // CHECK: -VarDecl {{.*}} p 'int * __cheri_[[SK]]_sealed'
  // CHECK-NEXT: -ImplicitCastExpr {{.*}} 'int * __cheri_[[SK]]_sealed'
  int * p = &x;
  // CHECK: -BinaryOperator {{.*}} 'int' '='
  // CHECK-NEXT: -UnaryOperator {{.*}} '*'
  // CHECK-NEXT: -ImplicitCastExpr {{.*}} 'int *' <[[XUtU]]>
  // CHECK-NEXT: -ImplicitCastExpr {{.*}} 'int *' <[[StXU]]>
  // CHECK-NEXT: -ImplicitCastExpr {{.*}} 'int * __cheri_[[SK]]_sealed' <LValueToRValue>
  *p = 1;

  typedef int *PSI;
  typedef int *UNSEALED PI;
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
  // CHECK: -VarDecl {{.*}} p 'int * __cheri_[[SK]]_sealed'
  // CHECK-NEXT: -ImplicitCastExpr {{.*}} 'int * __cheri_[[SK]]_sealed' <[[XUtS]]>
  // CHECK-NEXT: -ImplicitCastExpr {{.*}} 'int *' <ArrayToPointerDecay>
  int *p = x;

  // CHECK: -BinaryOperator {{.*}} '='
  // CHECK-NEXT: -DeclRefExpr
  // CHECK-NEXT: -ImplicitCastExpr {{.*}} 'int * __cheri_[[SK]]_sealed' <[[XUtS]]>
  // CHECK-NEXT: -BinaryOperator {{.*}} '+'
  // CHECK-NEXT: -ImplicitCastExpr {{.*}} 'int *' <[[StXU]]>
  p = p + 1;

  int *q = p - 1;
  int *UNSEALED r = x;

  // CHECK: -VarDecl {{.*}} d 'ptrdiff_t'
  // CHECK-NEXT: -BinaryOperator {{.*}} '-'
  // CHECK: -ImplicitCastExpr {{.*}} 'int *'
  // CHECK: -DeclRefExpr {{.*}} 'p'
  // CHECK: -ImplicitCastExpr {{.*}} 'int *'
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
  // CHECK-NEXT: -ImplicitCastExpr {{.*}} 'int * __cheri_[[SK]]_sealed' <NullToPointer>
  p = NULL;

  p = (p >= q) ? p : __builtin_cheri_trust_capability(r);
  p = ((void) p,p);

  int a[3];
  int *px = a;

  (void)(1 ? a : px);
  (void)(1 ? r : px);
  (void)(1 ? r : px+1);
  (void)(1 ? px : px+1);
}

struct S
{
  int *p, *p1;
  int *UNSEALED q;
  int *r;
};

union U
{
  int *p;
#pragma pointer_sealing unsealed
  int * q;
#pragma pointer_sealing SK
};

int x;
// CHECK-LABEL: |-FunctionDecl 0x{{.*}} structs 'void (void)'
void structs(void) {
  // initializations and assignment
  // CHECK: -VarDecl {{.*}} s 'struct S'
  // CHECK-NEXT: -InitListExpr
  // CHECK-NEXT: -ImplicitCastExpr {{.*}} 'int * __cheri_[[SK]]_sealed' <[[XUtS]]>
  struct S s = {.p = &x, .p1 = &x, .q = &x, .r = &x};
  // CHECK: -CompoundLiteralExpr {{.*}} 'struct S'
  // CHECK-NEXT: -InitListExpr
  // CHECK-NEXT: -ImplicitCastExpr {{.*}} 'int * __cheri_[[SK]]_sealed' <[[XUtS]]>
  s = (struct S){.p = &x, .p1 = &x, .q = &x, .r = &x};

  // use through a sealed capability
  struct S *sp = &s;
  // CHECK: -BinaryOperator {{.*}} 'int * __cheri_[[SK]]_sealed' '='
  // CHECK-NEXT: -MemberExpr
  // CHECK-NEXT: -ImplicitCastExpr {{.*}} 'struct S *' <[[XUtU]]>
  // CHECK-NEXT: -ImplicitCastExpr {{.*}} 'struct S *' <[[StXU]]>
  sp->p = &x;
}

// CHECK-LABEL: |-FunctionDecl 0x{{.*}} unions 'void (void)'
void unions(void) {
  // CHECK: -VarDecl {{.*}} u 'union U'
  // CHECK-NEXT: -InitListExpr
  // CHECK-NEXT: -ImplicitCastExpr {{.*}} 'int * __cheri_[[SK]]_sealed' <[[XUtS]]>
  union U u = {.p = &x};
  union U u1 = {.q = &x};
  // CHECK: -CompoundLiteralExpr {{.*}} 'union U'
  // CHECK-NEXT: -InitListExpr
  // CHECK-NEXT: -ImplicitCastExpr {{.*}} 'int * __cheri_[[SK]]_sealed' <[[XUtS]]>
  u = (union U){.p = &x};
  u = (union U){.q = &x};

  // CHECK: -BinaryOperator {{.*}} 'int * __cheri_[[SK]]_sealed' '='
  // CHECK-NEXT: -MemberExpr
  // CHECK-NEXT: -DeclRefExpr
  // CHECK-NEXT: -ImplicitCastExpr {{.*}} 'int * __cheri_[[SK]]_sealed' <[[XUtS]]>
  u.p = &x;
  u.q = &x;

  // Use through a sealed capability
  union U *up = &u;
  // CHECK: -BinaryOperator {{.*}} 'int * __cheri_[[SK]]_sealed' '='
  // CHECK-NEXT: -MemberExpr
  // CHECK-NEXT: -ImplicitCastExpr {{.*}} 'union U *' <[[XUtU]]>
  // CHECK-NEXT: -ImplicitCastExpr {{.*}} 'union U *' <[[StXU]]>
  up->p = &x;
}

// CHECK-LABEL: |-FunctionDecl 0x{{.*}} arrays 'void (void)'
void arrays(void) {
  // array of sealed capabilities
  // CHECK: -VarDecl {{.*}} a 'int * __cheri_[[SK]]_sealed([2]
  // CHECK-NEXT: -InitListExpr
  // CHECK-NEXT: -ImplicitCastExpr {{.*}} 'int * __cheri_[[SK]]_sealed'{{.*}} <[[XUtS]]>
  int * (a[2]) = {&x, &x};

  // write to array elements
  // CHECK: -BinaryOperator {{.*}} 'int * __cheri_[[SK]]_sealed'{{.*}} '='
  // CHECK: -ArraySubscriptExpr
  // CHECK: -ImplicitCastExpr {{.*}} 'int * __cheri_[[SK]]_sealed'{{.*}} <[[XUtS]]>
  a[1] = &x;

  // struct containing an array of sealed capabilities
  // CHECK: -VarDecl {{.*}} sa 'struct SA{{.*}}
  // CHECK-NEXT: -InitListExpr
  // CHECK-NEXT: -InitListExpr
  // CHECK-NEXT: -ImplicitCastExpr {{.*}} 'int * __cheri_[[SK]]_sealed' <[[XUtS]]>
  struct SA {int *a[2];} sa = {.a = {&x,&x}};
  sa = (struct SA) {.a = {&x, &x}};

  int *((*ap)[2]) = &a;
  // Pointers to arrays are unsealed
  // CHECK: -BinaryOperator {{.*}} 'int * __cheri_[[SK]]_sealed'{{.*}} '='
  // CHECK-NEXT: -ArraySubscriptExpr
  // CHECK: -ImplicitCastExpr {{.*}} 'int * __cheri_[[SK]]_sealed((*)[2])' <[[StXU]]>
  (*ap)[1] = &x;
}

// CHECK-LABEL: |-FunctionDecl 0x{{.*}} f
int *f(int *p)
{
  return p;
}

typedef int *(*UNSEALED FP)(int *p);
typedef int *(*SFP)(int *p);
typedef int *UNSEALED(*UNSEALED FP2)(int *p);
typedef int *(*UNSEALED FP3)(int *UNSEALED p);

// CHECK-LABEL: |-FunctionDecl 0x{{.*}} functions 'void (void)'
void functions(void)
{
  // should seal argument
  // CHECK: -VarDecl {{.*}} p 'int * __cheri_[[SK]]_sealed'
  // CHECK-NEXT: -CallExpr
  // CHECK-NEXT: -ImplicitCastExpr {{.*}} <FunctionToPointerDecay>
  // CHECK-NEXT: -DeclRefExpr
  // CHECK-NEXT: -ImplicitCastExpr {{.*}} 'int * __cheri_[[SK]]_sealed' <[[XUtS]]>
  int *p = f(&x);

  // can have sealed function pointers
  // CHECK: -VarDecl {{.*}} sfp 'SFP'
  // CHECK-NEXT: -ImplicitCastExpr {{.*}} 'SFP'{{.*}} <[[XUtS]]>
  SFP sfp = f;

  // Unsealing sealed function pointers
  // CHECK: -VarDecl {{.*}} fp 'FP'
  // CHECK-NEXT: -ImplicitCastExpr {{.*}} 'FP'{{.*}} <[[XUtU]]>
  // CHECK-NEXT: -ImplicitCastExpr {{.*}} {{.*}} <[[StXU]]>
  FP fp = sfp;

  //sealedness is a part of the function pointer type
  FP2 fp2 = f; // expected-warning {{incompatible function pointer types initializing}}
  FP3 fp3 = f; // expected-warning {{incompatible function pointer types initializing}}
}

// CHECK-LABEL: -FunctionDecl 0x{{.*}} explicit_casts 'void (void)'
void explicit_casts(void)
{
  int *sp = (int *)&x;
  int *nsp = (int *) NULL;
  int *UNSEALED p = (int*UNSEALED) sp;
  double *sdp = (double *) sp;
}

#pragma pointer_sealing unsealed
