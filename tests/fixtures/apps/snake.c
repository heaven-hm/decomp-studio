/* Snake: deterministic simulation. A seeded PRNG drives the food and the
 * snake's turn decisions. Prints each frame as text. Exercises arrays,
 * queues, bit ops, multiply/divide/shift and heavy branching. */
#include "fy.h"

#define W 20
#define H 12

static u32 rng_state = 0x12345678u;
static u32 rng(void) {
  rng_state ^= rng_state << 13;
  rng_state ^= rng_state >> 17;
  rng_state ^= rng_state << 5;
  return rng_state;
}

static int body_x[256];
static int body_y[256];
static int body_len;
static int food_x, food_y;
static int score;
static int alive;
static char grid[H][W];

static int occupied(int x, int y) {
  for (int i = 0; i < body_len; i++)
    if (body_x[i] == x && body_y[i] == y) return 1;
  return 0;
}

static void place_food(void) {
  for (int tries = 0; tries < 10000; tries++) {
    int x = (int)(rng() % W);
    int y = (int)(rng() % H);
    if (!occupied(x, y)) { food_x = x; food_y = y; return; }
  }
  food_x = 0; food_y = 0;
}

static void render(void) {
  for (int y = 0; y < H; y++) {
    for (int x = 0; x < W; x++) {
      char c = '.';
      if (x == food_x && y == food_y) c = '*';
      grid[y][x] = c;
    }
  }
  for (int i = 0; i < body_len; i++)
    grid[body_y[i]][body_x[i]] = i == 0 ? '@' : 'o';
  for (int y = 0; y < H; y++) {
    for (int x = 0; x < W; x++) outc(grid[y][x]);
    crlf();
  }
}

int app_main(void) {
  out("snake:start"); crlf();
  body_len = 1;
  body_x[0] = W / 2; body_y[0] = H / 2;
  score = 0;
  alive = 1;
  place_food();

  int dx = 1, dy = 0;
  for (int step = 0; step < 48 && alive; step++) {
    /* Every third step, steer toward the food (simple greedy AI). */
    if (step % 3 == 0) {
      int hx = body_x[0], hy = body_y[0];
      if (food_x != hx) { dx = food_x > hx ? 1 : -1; dy = 0; }
      else if (food_y != hy) { dx = 0; dy = food_y > hy ? 1 : -1; }
    }
    int nx = body_x[0] + dx;
    int ny = body_y[0] + dy;
    if (nx < 0 || nx >= W || ny < 0 || ny >= H) { alive = 0; break; }
    if (occupied(nx, ny)) { alive = 0; break; }
    int ate = (nx == food_x && ny == food_y);
    if (!ate) {
      for (int i = body_len - 1; i > 0; i--) {
        body_x[i] = body_x[i - 1];
        body_y[i] = body_y[i - 1];
      }
    } else {
      for (int i = body_len; i > 0; i--) {
        body_x[i] = body_x[i - 1];
        body_y[i] = body_y[i - 1];
      }
      body_len++;
      score += 10;
      place_food();
    }
    body_x[0] = nx; body_y[0] = ny;
  }

  render();
  out("score="); outi(score);
  out(" len="); outi(body_len);
  out(" alive="); outi(alive); crlf();
  out("snake:done"); crlf();
  return 0;
}
