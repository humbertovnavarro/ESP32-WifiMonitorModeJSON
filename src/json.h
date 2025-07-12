#ifndef JSON_UTILS_H
#define JSON_UTILS_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Escapes a raw C string for safe inclusion in a JSON string value.
 *
 * The returned string is dynamically allocated and must be freed by the caller.
 *
 * Example input:  Hello "world"\n
 * Output:         Hello \"world\"\\n
 *
 * @param input Null-terminated input string to escape.
 * @return A newly allocated escaped string, or NULL on allocation failure.
 */
char* json_escape_string(const char* input);

#ifdef __cplusplus
}
#endif

#endif // JSON_UTILS_H
