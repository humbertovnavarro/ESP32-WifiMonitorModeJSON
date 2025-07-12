#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

char* json_escape_string(const char* input) {
    size_t len = strlen(input);
    size_t out_size = len * 6 + 1;  // worst case: every char becomes \u00XX
    char* output = malloc(out_size);
    if (!output) return NULL;

    char* p = output;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = input[i];
        switch (c) {
            case '\"': *p++ = '\\'; *p++ = '\"'; break;
            case '\\': *p++ = '\\'; *p++ = '\\'; break;
            case '\b': *p++ = '\\'; *p++ = 'b';  break;
            case '\f': *p++ = '\\'; *p++ = 'f';  break;
            case '\n': *p++ = '\\'; *p++ = 'n';  break;
            case '\r': *p++ = '\\'; *p++ = 'r';  break;
            case '\t': *p++ = '\\'; *p++ = 't';  break;
            default:
                if (c < 0x20) {
                    sprintf(p, "\\u%04x", c);
                    p += 6;
                } else {
                    *p++ = c;
                }
        }
    }
    *p = '\0';
    return output;
}
