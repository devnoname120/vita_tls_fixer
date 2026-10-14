#ifndef VITA_TLS_CHECK_INPUT_H
#define VITA_TLS_CHECK_INPUT_H
#include <stdint.h>
typedef struct {
    int direction;
    uint64_t next_ms;
} CheckScrollRepeat;
int check_scroll_direction(int up, int down, unsigned left_y, unsigned right_y);
/* Immediate first step; 220ms initial delay, then 40ms repeat. */
int check_scroll_repeat(CheckScrollRepeat *repeat, int direction, uint64_t now_ms);
unsigned check_scroll_move(unsigned scroll, int steps, unsigned count, unsigned visible);
#endif
