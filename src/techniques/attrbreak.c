#include "techniques.h"
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

static bool ci_strstr(const char *haystack, const char *needle) {
    if (!haystack || !needle) return false;
    size_t h_len = strlen(haystack);
    size_t n_len = strlen(needle);
    if (n_len > h_len || n_len == 0) return false;
    
    for (size_t i = 0; i <= h_len - n_len; i++) {
        bool match = true;
        for (size_t j = 0; j < n_len && match; j++) {
            if (tolower((unsigned char)haystack[i+j]) != tolower((unsigned char)needle[j]))
                match = false;
        }
        if (match) return true;
    }
    return false;
}

static const char *ci_find(const char *haystack, const char *needle) {
    if (!haystack || !needle) return NULL;
    size_t h_len = strlen(haystack);
    size_t n_len = strlen(needle);
    if (n_len > h_len || n_len == 0) return NULL;
    
    for (size_t i = 0; i <= h_len - n_len; i++) {
        bool match = true;
        for (size_t j = 0; j < n_len && match; j++) {
            if (tolower((unsigned char)haystack[i+j]) != tolower((unsigned char)needle[j]))
                match = false;
        }
        if (match) return haystack + i;
    }
    return NULL;
}

bool technique_attribute_breakout(const char *response, const char *payload, detection_result_t *result) {
    if (!response || !payload || strlen(payload) == 0) {
        result->vulnerable = false;
        return false;
    }
    
    result->vulnerable = false;
    result->confidence = 0;
    result->reason = NULL;
    result->context = CTX_UNKNOWN;
    
    bool has_quote = strchr(payload, '"') || strchr(payload, '\'');
    bool has_angle = strchr(payload, '<') || strchr(payload, '>');
    
    if (!has_quote && !has_angle) return false;
    
    const char *pay_pos = ci_find(response, payload);
    if (!pay_pos) return false;
    
    const char *scan = pay_pos;
    while (scan > response && *scan != '<' && *scan != '>') scan--;
    
    if (*scan != '<') return false;
    
    const char *tag_end = strchr(scan, '>');
    if (!tag_end || tag_end < pay_pos) {
        bool in_attr = false;
        char quote_char = 0;
        
        for (const char *p = scan; p < pay_pos; p++) {
            if (*p == '=' && !in_attr) {
                p++;
                while (p < pay_pos && isspace(*p)) p++;
                if (p < pay_pos && (*p == '"' || *p == '\'')) {
                    in_attr = true;
                    quote_char = *p;
                } else if (p < pay_pos) {
                    in_attr = true;
                    quote_char = 0;
                }
            }
            if (in_attr && quote_char && *p == quote_char && p > scan + 1) {
                in_attr = false;
                quote_char = 0;
            }
        }
        
        if (in_attr) {
            if (quote_char == '"' && strchr(payload, '"')) {
                result->vulnerable = true;
                result->confidence = 94;
                result->reason = "double quote attribute breakout";
                result->context = CTX_ATTR_VALUE_DOUBLE;
                return true;
            }
            if (quote_char == '\'' && strchr(payload, '\'')) {
                result->vulnerable = true;
                result->confidence = 94;
                result->reason = "single quote attribute breakout";
                result->context = CTX_ATTR_VALUE_SINGLE;
                return true;
            }
            if (quote_char == 0 && (strchr(payload, ' ') || strchr(payload, '>'))) {
                result->vulnerable = true;
                result->confidence = 90;
                result->reason = "unquoted attribute breakout";
                result->context = CTX_ATTR_VALUE_UNQUOTED;
                return true;
            }
        }
    }
    
    const char *breakout_patterns[] = {
        "\"><", "'><", " ><", "/>", "'>", "\">",
        "\" ", "' ", "\"autofocus", "'autofocus",
        NULL
    };
    
    for (int i = 0; breakout_patterns[i]; i++) {
        if (ci_strstr(payload, breakout_patterns[i])) {
            if (ci_strstr(response, payload)) {
                result->vulnerable = true;
                result->confidence = 92;
                result->reason = "attribute breakout pattern";
                result->context = CTX_ATTR_VALUE_DOUBLE;
                return true;
            }
        }
    }
    
    return false;
}
