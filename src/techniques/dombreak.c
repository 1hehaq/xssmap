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

bool technique_dom_breakout(const char *response, const char *payload, detection_result_t *result) {
    if (!response || !payload || strlen(payload) == 0) {
        result->vulnerable = false;
        return false;
    }
    
    result->vulnerable = false;
    result->confidence = 0;
    result->reason = NULL;
    result->context = CTX_UNKNOWN;
    
    const char *breakout_sequences[] = {
        "</script>", "</SCRIPT>", "</ScRiPt>",
        "</style>", "</STYLE>",
        "</title>", "</TITLE>",
        "</textarea>", "</TEXTAREA>",
        "</noscript>", "</NOSCRIPT>",
        "</xmp>", "</plaintext>", "</listing>",
        "</noframes>", "</comment>",
        "-->", "--!>",
        "]]>",
        NULL
    };
    
    for (int i = 0; breakout_sequences[i]; i++) {
        if (ci_strstr(payload, breakout_sequences[i])) {
            if (ci_strstr(response, payload)) {
                result->vulnerable = true;
                result->confidence = 96;
                result->reason = "context breakout sequence";
                result->context = CTX_SCRIPT_DATA;
                return true;
            }
        }
    }
    
    const char *script_breakouts[] = {
        "';", "\";", "`;",
        "'-", "\"-",
        "//", "/*",
        "\\n", "\\r",
        NULL
    };
    
    if (ci_strstr(payload, "</script") || ci_strstr(payload, "<script")) {
        for (int i = 0; script_breakouts[i]; i++) {
            if (ci_strstr(payload, script_breakouts[i])) {
                if (ci_strstr(response, payload)) {
                    result->vulnerable = true;
                    result->confidence = 94;
                    result->reason = "script context breakout";
                    result->context = CTX_SCRIPT_DATA;
                    return true;
                }
            }
        }
    }
    
    return false;
}
