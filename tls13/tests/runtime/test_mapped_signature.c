#include "mapped_signature.h"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>

static void encode(uint8_t *out, unsigned immediate, unsigned movt) {
    uint16_t first = (uint16_t)((movt ? 0xF2C0u : 0xF240u) |
        ((immediate >> 12) & 15u) | (((immediate >> 11) & 1u) << 10));
    uint16_t second = (uint16_t)(0x0800u | (((immediate >> 8) & 7u) << 12) | (immediate & 255u));
    out[0]=(uint8_t)first;out[1]=(uint8_t)(first>>8);
    out[2]=(uint8_t)second;out[3]=(uint8_t)(second>>8);
}

int main(void) {
    uint8_t code[18] = {0x2d,0xe9,0xf0,0x41,0x88,0xb0,0x49,0xf6,0,0x18,0xc8,0xf2,1,0x18,0xd8,0xf8,0,0x20};
    assert(tls_fixer_http_create_mov_pair_valid(code,sizeof(code)));
    for (unsigned immediate=0;immediate<65536;++immediate) {
        encode(code+6,immediate,0);encode(code+10,65535-immediate,1);
        assert(tls_fixer_http_create_mov_pair_valid(code,sizeof(code)));
    }
    for (unsigned instruction=0;instruction<2;++instruction) {
        unsigned offset=6+4*instruction;
        for (unsigned byte=0;byte<4;++byte) {
            const unsigned masks[]={0xf0,0xfb,0,0x8f};
            for (unsigned bit=0;bit<8;++bit) {
                if (!(masks[byte]&(1u<<bit)))continue;
                code[offset+byte]^=(uint8_t)(1u<<bit);
                assert(!tls_fixer_http_create_mov_pair_valid(code,sizeof(code)));
                code[offset+byte]^=(uint8_t)(1u<<bit);
            }
        }
    }
    assert(!tls_fixer_http_create_mov_pair_valid(NULL,sizeof(code)));
    assert(!tls_fixer_http_create_mov_pair_valid(code,17));
    puts("MOVW/MOVT relocation fields accepted; opcode/register mutations rejected");
}
