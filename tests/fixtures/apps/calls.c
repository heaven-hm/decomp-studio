/* Calling-convention and indirect-call fixture.
 *
 * Exercises direct calls, recursion, register and stack argument passing
 * (more than four arguments), function pointers dispatched through a table,
 * and a vtable-style struct, so a wrong stack layout or a broken indirect-call
 * dispatch changes the printed results. */
#include "fy.h"

typedef i64 (*Operation)(i64, i64);

static i64 add_values(i64 left, i64 right) { return left + right; }
static i64 subtract_values(i64 left, i64 right) { return left - right; }
static i64 multiply_values(i64 left, i64 right) { return left * right; }
static i64 max_values(i64 left, i64 right) { return left > right ? left : right; }

static Operation operations[4] = {add_values, subtract_values, multiply_values, max_values};

static i64 sum_eight(i64 a, i64 b, i64 c, i64 d, i64 e, i64 f, i64 g, i64 h) {
  return a + b + c + d + e + f + g + h;
}

static i64 factorial(i64 value) {
  if (value <= 1) return 1;
  return value * factorial(value - 1);
}

static i64 ackermann(i64 m, i64 n) {
  if (m == 0) return n + 1;
  if (n == 0) return ackermann(m - 1, 1);
  return ackermann(m - 1, ackermann(m, n - 1));
}

typedef struct {
  i64 base;
  Operation apply;
  i64 (*scale)(i64 value, i64 factor);
} Transformer;

static i64 scale_by(i64 value, i64 factor) { return value * factor; }

static i64 run_transformer(const Transformer* transformer, i64 input) {
  i64 intermediate = transformer->apply(transformer->base, input);
  return transformer->scale(intermediate, 3);
}

int app_main(void) {
  out("calls:start"); crlf();

  /* Register arguments. */
  out("sum4="); outi(sum_eight(1, 2, 3, 4, 0, 0, 0, 0)); crlf();
  /* Stack arguments beyond the fourth. */
  out("sum8="); outi(sum_eight(1, 2, 3, 4, 5, 6, 7, 8)); crlf();
  /* Reversed operands to expose argument-order mistakes. */
  out("sum8_rev="); outi(sum_eight(8, 7, 6, 5, 4, 3, 2, 1)); crlf();

  /* Recursion. */
  out("factorial(12)="); outi(factorial(12)); crlf();
  out("ackermann(2,3)="); outi(ackermann(2, 3)); crlf();

  /* Indirect calls through a table. */
  i64 accumulated = 0;
  for (int index = 0; index < 4; index++) accumulated = operations[index](accumulated, index + 2);
  out("table_dispatch="); outi(accumulated); crlf();

  /* Indirect calls through a struct of function pointers. */
  Transformer transformer;
  transformer.base = 10;
  transformer.apply = add_values;
  transformer.scale = scale_by;
  out("transformer="); outi(run_transformer(&transformer, 7)); crlf();

  transformer.apply = multiply_values;
  out("transformer_mul="); outi(run_transformer(&transformer, 7)); crlf();

  out("calls:done"); crlf();
  return 0;
}
