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

bool technique_script_injection(const char *response, const char *payload, detection_result_t *result) {
    if (!response || !payload || strlen(payload) == 0) {
        result->vulnerable = false;
        return false;
    }
    
    result->vulnerable = false;
    result->confidence = 0;
    result->reason = NULL;
    result->context = CTX_UNKNOWN;
    
    const char *script_starters[] = {
        "<script>", "<script ", "<script/", "<script\t", "<script\n",
        "<SCRIPT>", "<SCRIPT ", "<ScRiPt>", "<ScRiPt ",
        NULL
    };
    
    for (int i = 0; script_starters[i]; i++) {
        if (ci_strstr(payload, script_starters[i])) {
            const char *pos = ci_find(response, script_starters[i]);
            if (pos) {
                const char *pay_pos = ci_find(response, payload);
                if (pay_pos) {
                    result->vulnerable = true;
                    result->confidence = 98;
                    result->reason = "script tag injection";
                    result->context = CTX_SCRIPT_DATA;
                    return true;
                }
            }
        }
    }
    
    const char *dangerous_tags[] = {
        "<svg", "<img", "<video", "<audio", "<iframe", "<object", 
        "<embed", "<math", "<details", "<marquee", "<body",
        "<input", "<button", "<select", "<textarea", "<form",
        "<isindex", "<keygen", "<meter", "<progress",
        NULL
    };
    
    const char *trigger_events[] = {
        "onerror=", "onload=", "onfocus=", "onclick=", "onmouseover=",
        "onmouseenter=", "onanimationend=", "ontransitionend=",
        "onbegin=", "autofocus", "onfocusin=",
        NULL
    };
    
    for (int t = 0; dangerous_tags[t]; t++) {
        if (ci_strstr(payload, dangerous_tags[t])) {
            for (int e = 0; trigger_events[e]; e++) {
                if (ci_strstr(payload, trigger_events[e])) {
                    if (ci_strstr(response, payload)) {
                        result->vulnerable = true;
                        result->confidence = 95;
                        result->reason = "tag with event handler";
                        result->context = CTX_HTML_TEXT;
                        return true;
                    }
                }
            }
        }
    }
    
    return false;
}
