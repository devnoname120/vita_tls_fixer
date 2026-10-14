#include "input.h"
int check_scroll_direction(int up, int down, unsigned left_y, unsigned right_y) {
    if (up || down) return !!down - !!up;
    int stick_up = left_y < 80 || right_y < 80;
    int stick_down = left_y > 175 || right_y > 175;
    return stick_down - stick_up;
}
int check_scroll_repeat(CheckScrollRepeat *repeat, int direction, uint64_t now_ms) {
    if (!direction) {
        repeat->direction = 0;
        repeat->next_ms = 0;
        return 0;
    }
    if (direction != repeat->direction) {
        repeat->direction = direction;
        repeat->next_ms = now_ms + 220;
        return direction;
    }
    if (now_ms < repeat->next_ms) return 0;
    uint64_t count = 1 + (now_ms - repeat->next_ms) / 40;
    /* Bound catch-up after a slow frame instead of retaining a repeat backlog. */
    if (count > 8) {
        count = 8;
        repeat->next_ms = now_ms + 40;
    } else repeat->next_ms += count * 40;
    return direction * (int)count;
}
unsigned check_scroll_move(unsigned scroll, int steps, unsigned count, unsigned visible) {
    unsigned limit = count > visible ? count - visible : 0;
    if (scroll > limit) scroll = limit;
    if (steps < 0) return (unsigned)(-steps) > scroll ? 0 : scroll - (unsigned)(-steps);
    return (unsigned)steps > limit - scroll ? limit : scroll + (unsigned)steps;
}
