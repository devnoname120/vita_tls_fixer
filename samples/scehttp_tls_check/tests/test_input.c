#include "input.h"
#include <assert.h>
#include <stdio.h>
int main(void) {
    assert(check_scroll_direction(0, 0, 127, 128) == 0);
    assert(check_scroll_direction(1, 0, 255, 255) == -1);
    assert(check_scroll_direction(0, 1, 0, 0) == 1);
    assert(check_scroll_direction(1, 1, 127, 127) == 0);
    assert(check_scroll_direction(0, 0, 79, 128) == -1);
    assert(check_scroll_direction(0, 0, 128, 176) == 1);
    assert(check_scroll_direction(0, 0, 80, 175) == 0);
    assert(check_scroll_direction(0, 0, 0, 255) == 0);
    CheckScrollRepeat r = {0};
    assert(check_scroll_repeat(&r, 1, 100) == 1);
    assert(check_scroll_repeat(&r, 1, 319) == 0);
    assert(check_scroll_repeat(&r, 1, 320) == 1);
    assert(check_scroll_repeat(&r, 1, 359) == 0);
    assert(check_scroll_repeat(&r, 1, 440) == 3);
    assert(check_scroll_repeat(&r, -1, 441) == -1);
    assert(check_scroll_repeat(&r, -1, 660) == 0);
    assert(check_scroll_repeat(&r, 0, 661) == 0);
    assert(check_scroll_repeat(&r, -1, 662) == -1);
    assert(check_scroll_repeat(&r, -1, 10000) == -8);
    assert(check_scroll_repeat(&r, -1, 10001) == 0);
    assert(check_scroll_move(0, -8, 20, 5) == 0);
    assert(check_scroll_move(13, 8, 20, 5) == 15);
    assert(check_scroll_move(15, -3, 20, 5) == 12);
    assert(check_scroll_move(15, 0, 2, 5) == 0);
    assert(check_scroll_move(0, 8, 0, 5) == 0);
    puts("D-pad/stick dead zones, immediate/repeated holds, release/reversal and scroll bounds: PASS");
}
