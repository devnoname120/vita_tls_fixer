/* SPDX-License-Identifier: 0BSD */
#include "json_stream.h"
#include <string.h>
enum { OBJECT=1, ARRAY };
enum { FIRST=0, NEXT, COLON, VALUE, AFTER };
enum { OTHER=0, ROOT, IMAGES, IMAGE };
enum { NONE=0, ID, IMAGE_LIST, URL, TYPE };
enum { STRING=1, NUMBER, LITERAL };
enum { SIGN=1, ZERO, INTEGER, DOT, FRACTION, EXPONENT, EXP_SIGN, EXP_DIGITS };
static int ws(unsigned c) {return c==' '||c=='\t'||c=='\r'||c=='\n';}
static int hex(unsigned c) {
    if(c>='0'&&c<='9')return (int)c-'0';
    if(c>='a'&&c<='f')return (int)c-'a'+10;
    if(c>='A'&&c<='F')return (int)c-'A'+10;
    return -1;
}
static void save(StoreJsonStream *s,unsigned c) {
    if(!s->capture)return;
    if(c==0||c>127||s->token_length+1>=sizeof(s->token))s->token_overflow=1;
    if(!s->token_overflow)s->token[s->token_length++]=(char)c;
}
static void token_start(StoreJsonStream *s,int capture) {
    s->token_length=s->token_overflow=0;s->capture=(unsigned)capture;s->token[0]=0;
}
static void value_done(StoreJsonStream *s) {s->frames[s->depth-1].state=AFTER;}
static int string_done(StoreJsonStream *s) {
    StoreJsonFrame *f=&s->frames[s->depth-1];
    s->token[s->token_overflow?0:s->token_length]=0;
    if(s->string_is_key) {
        f->key=NONE;unsigned bit=0;
        if(f->role==ROOT) {
            if(!strcmp(s->token,"id")){f->key=ID;bit=1;}
            if(!strcmp(s->token,"images")){f->key=IMAGE_LIST;bit=2;}
        } else if(f->role==IMAGE) {
            if(!strcmp(s->token,"url")){f->key=URL;bit=1;}
            if(!strcmp(s->token,"type")){f->key=TYPE;bit=2;}
        }
        if(f->seen&bit)return -1;
        f->seen|=(unsigned char)bit;f->state=COLON;
    } else {
        if(f->role==ROOT&&f->key==ID) {
            if(s->token_overflow||s->token_length!=STORE_COVER_ID_SIZE-1)return -1;
            memcpy(s->product,s->token,STORE_COVER_ID_SIZE);
        } else if(f->role==IMAGE&&f->key==URL) {
            if(s->token_overflow)s->candidate[0]=0;
            else memcpy(s->candidate,s->token,s->token_length+1);
        }
        value_done(s);
    }
    s->lex=0;return 0;
}
static int number_terminal(unsigned state) {return state==ZERO||state==INTEGER||state==FRACTION||state==EXP_DIGITS;}
static void number_done(StoreJsonStream *s) {
    StoreJsonFrame *f=&s->frames[s->depth-1];
    if(f->role==IMAGE&&f->key==TYPE)
        f->type10=!s->token_overflow&&s->token_length==2&&s->token[0]=='1'&&s->token[1]=='0';
    value_done(s);s->lex=0;
}
static int close_container(StoreJsonStream *s) {
    StoreJsonFrame *f=&s->frames[s->depth-1];
    if(f->role==IMAGE && f->type10 && !s->image[0] && store_cover_valid_url(s->candidate))
        memcpy(s->image,s->candidate,strlen(s->candidate)+1);
    if(f->role==ROOT)s->root_seen=f->seen;
    --s->depth;
    if(!s->depth)s->done=1;else value_done(s);
    return 0;
}
static int begin_value(StoreJsonStream *s,unsigned c) {
    StoreJsonFrame *parent=s->depth?&s->frames[s->depth-1]:NULL;
    unsigned role=OTHER, key=parent?parent->key:NONE;
    if(!parent) {if(c!='{')return -1;role=ROOT;}
    else if(parent->role==ROOT) {
        if(key==ID && c!='"')return -1;
        if(key==IMAGE_LIST) {if(c!='[')return -1;role=IMAGES;}
    } else if(parent->role==IMAGES) {if(c!='{')return -1;role=IMAGE;}
    else if(parent->role==IMAGE) {
        if(key==URL && c!='"')return -1;
        if(key==TYPE && c!='-' && (c<'0'||c>'9'))return -1;
    }
    if(c=='{'||c=='[') {
        if(s->depth==STORE_JSON_DEPTH)return -1;
        s->frames[s->depth++]=(StoreJsonFrame){c=='{'?OBJECT:ARRAY,FIRST,(unsigned char)role,0,0,0};
        if(role==IMAGE)s->candidate[0]=0;
        return 0;
    }
    if(!parent)return -1;
    if(c=='"') {s->lex=STRING;s->string_is_key=0;token_start(s,(parent->role==ROOT&&key==ID)||(parent->role==IMAGE&&key==URL));return 0;}
    if(c=='-'||(c>='0'&&c<='9')) {
        s->lex=NUMBER;s->number_state=c=='-'?SIGN:c=='0'?ZERO:INTEGER;
        token_start(s,parent->role==IMAGE&&key==TYPE);save(s,c);return 0;
    }
    if(c=='t'||c=='f'||c=='n') {s->lex=LITERAL;s->literal_kind=c;s->literal_position=1;return 0;}
    return -1;
}
int store_json_init(StoreJsonStream *s,const char *id) {
    if(!s)return -1;
    memset(s,0,sizeof(*s));
    if(!store_cover_valid_id(id)){s->error=1;return -1;}
    memcpy(s->expected,id,STORE_COVER_ID_SIZE);return 0;
}
int store_json_feed(StoreJsonStream *s,const char *bytes,size_t length) {
    if(!s||s->error||(!bytes&&length))return -1;
    size_t at=0;
    while(at<length) {
        unsigned c=(unsigned char)bytes[at++];
        if(s->lex==STRING) {
            if(s->unicode_left) {int h=hex(c);if(h<0)goto bad;s->unicode_value=s->unicode_value*16u+(unsigned)h;if(!--s->unicode_left)save(s,s->unicode_value);continue;}
            if(s->escape) {
                s->escape=0;
                if(c=='u'){s->unicode_left=4;s->unicode_value=0;continue;}
                if(c=='b')c=8;else if(c=='f')c=12;else if(c=='n')c=10;else if(c=='r')c=13;else if(c=='t')c=9;
                else if(c!='"'&&c!='\\'&&c!='/')goto bad;
                save(s,c);continue;
            }
            if(c=='\\'){s->escape=1;continue;}
            if(c=='"'){if(string_done(s)<0)goto bad;continue;}
            if(c<32)goto bad;
            save(s,c);continue;
        }
        if(s->lex==LITERAL) {
            const char *literal=s->literal_kind=='t'?"true":s->literal_kind=='f'?"false":"null";
            if(c!=(unsigned char)literal[s->literal_position++])goto bad;
            if(!literal[s->literal_position]){s->lex=0;value_done(s);}continue;
        }
        if(s->lex==NUMBER) {
            unsigned next=0;
            switch(s->number_state) {
            case SIGN: if(c=='0')next=ZERO;else if(c>='1'&&c<='9')next=INTEGER;break;
            case ZERO: if(c=='.')next=DOT;else if(c=='e'||c=='E')next=EXPONENT;break;
            case INTEGER: if(c>='0'&&c<='9')next=INTEGER;else if(c=='.')next=DOT;else if(c=='e'||c=='E')next=EXPONENT;break;
            case DOT: if(c>='0'&&c<='9')next=FRACTION;break;
            case FRACTION: if(c>='0'&&c<='9')next=FRACTION;else if(c=='e'||c=='E')next=EXPONENT;break;
            case EXPONENT: if(c=='+'||c=='-')next=EXP_SIGN;else if(c>='0'&&c<='9')next=EXP_DIGITS;break;
            case EXP_SIGN: case EXP_DIGITS: if(c>='0'&&c<='9')next=EXP_DIGITS;break;
            }
            if(next){s->number_state=next;save(s,c);continue;}
            if(!number_terminal(s->number_state))goto bad;
            number_done(s); /* Process the delimiter through the container state. */
        }
        if(ws(c))continue;
        if(s->done)goto bad;
        if(!s->depth){if(begin_value(s,c)<0)goto bad;continue;}
        StoreJsonFrame *f=&s->frames[s->depth-1];
        if(f->kind==OBJECT) {
            if(f->state==FIRST||f->state==NEXT) {
                if(c=='}'&&f->state==FIRST){close_container(s);continue;}
                if(c!='"')goto bad;
                s->lex=STRING;s->string_is_key=1;token_start(s,f->role==ROOT||f->role==IMAGE);continue;
            }
            if(f->state==COLON){if(c!=':')goto bad;f->state=VALUE;continue;}
            if(f->state==AFTER){if(c==','){f->state=NEXT;continue;}if(c=='}'){close_container(s);continue;}goto bad;}
        } else {
            if(f->state==FIRST&&c==']'){close_container(s);continue;}
            if(f->state==AFTER){if(c==','){f->state=NEXT;continue;}if(c==']'){close_container(s);continue;}goto bad;}
        }
        if(begin_value(s,c)<0)goto bad;
    }
    return 0;
bad:s->error=1;return -1;
}
int store_json_finish(const StoreJsonStream *s,char out[STORE_COVER_URL_SIZE]) {
    if(!out)return -1;
    out[0]=0;
    if(!s||s->error||!s->done||s->depth||s->lex||s->root_seen!=3||strcmp(s->expected,s->product)||!s->image[0])return -1;
    memcpy(out,s->image,strlen(s->image)+1);return 0;
}
