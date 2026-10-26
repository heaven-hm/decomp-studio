/* Arithmetic / control-flow fixture: exercises integer ops, flags, shifts,
 * multiply/divide, recursion and arrays. Deterministic textual output. */
#include "fy.h"

static u32 is_prime(u32 n) {
  if (n < 2) return 0;
  for (u32 d = 2; d * d <= n; d++) {
    if (n % d == 0) return 0;
  }
  return 1;
}

static u64 fib(int n) {
  if (n < 2) return (u64)n;
  return fib(n - 1) + fib(n - 2);
}

static i32 gcd(i32 a, i32 b) {
  while (b != 0) { i32 t = a % b; a = b; b = t; }
  return a < 0 ? -a : a;
}

static u32 popcount(u32 x) {
  u32 c = 0;
  while (x) { c += x & 1u; x >>= 1; }
  return c;
}

static u32 rotate(u32 x, int k) {
  return (x << k) | (x >> (32 - k));
}

int app_main(void) {
  out("arith:start"); crlf();

  u32 primes = 0;
  for (u32 n = 2; n < 200; n++) {
    if (is_prime(n)) primes++;
  }
  out("primes<200="); outi(primes); crlf();

  out("fib(20)="); outi((i64)fib(20)); crlf();
  out("gcd(1071,462)="); outi(gcd(1071, 462)); crlf();
  out("popcount(0xF0F0F0F0)="); outi(popcount(0xF0F0F0F0u)); crlf();
  out("rotl(0x12345678,8)="); outi((i64)rotate(0x12345678u, 8)); crlf();

  i64 acc = 0;
  int xs[16];
  for (int i = 0; i < 16; i++) xs[i] = i * i - 3 * i + 7;
  for (int i = 0; i < 16; i++) acc += xs[i] * (i + 1);
  out("poly="); outi(acc); crlf();

  i32 a = -12345, b = 678;
  out("mul="); outi((i64)a * b); crlf();
  out("div="); outi(a / b); crlf();
  out("mod="); outi(a % b); crlf();

  out("arith:done"); crlf();
  return 0;
}
