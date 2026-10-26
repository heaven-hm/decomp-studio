/* TicTacToe: deterministic AI vs AI using minimax. Exercises recursion,
 * arrays, loops and branching. Prints the whole game as text. */
#include "fy.h"

static char board[9];

static int winner(void) {
  static const int lines[8][3] = {
    {0,1,2},{3,4,5},{6,7,8},{0,3,6},{1,4,7},{2,5,8},{0,4,8},{2,4,6}
  };
  for (int i = 0; i < 8; i++) {
    int a = lines[i][0], b = lines[i][1], c = lines[i][2];
    if (board[a] != '.' && board[a] == board[b] && board[a] == board[c]) {
      return board[a] == 'X' ? 1 : -1;
    }
  }
  return 0;
}

static int full(void) {
  for (int i = 0; i < 9; i++) if (board[i] == '.') return 0;
  return 1;
}

static int minimax(char who, int depth, int* chosen) {
  int w = winner();
  if (w == 1) return 10 - depth;
  if (w == -1) return depth - 10;
  if (full()) return 0;

  int best = who == 'X' ? -1000 : 1000;
  int move = -1;
  for (int i = 0; i < 9; i++) {
    if (board[i] != '.') continue;
    board[i] = who;
    int score = minimax(who == 'X' ? 'O' : 'X', depth + 1, 0);
    board[i] = '.';
    if ((who == 'X' && score > best) || (who == 'O' && score < best)) {
      best = score;
      move = i;
    }
  }
  if (chosen) *chosen = move;
  return best;
}

static void render(void) {
  for (int r = 0; r < 3; r++) {
    for (int c = 0; c < 3; c++) outc(board[r * 3 + c]);
    crlf();
  }
  outc('-'); crlf();
}

int app_main(void) {
  out("tictactoe:start"); crlf();
  for (int i = 0; i < 9; i++) board[i] = '.';

  char who = 'X';
  int moves = 0;
  while (!winner() && !full()) {
    int move = -1;
    minimax(who, 0, &move);
    if (move < 0) break;
    board[move] = who;
    outc(who); outc(':'); outi(move); crlf();
    who = who == 'X' ? 'O' : 'X';
    moves++;
  }

  render();
  int w = winner();
  if (w == 1) out("result=X");
  else if (w == -1) out("result=O");
  else out("result=draw");
  out(" moves="); outi(moves);
  crlf();
  out("tictactoe:done"); crlf();
  return 0;
}
