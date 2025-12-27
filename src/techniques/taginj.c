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

bool technique_tag_injection(const char *response, const char *payload, detection_result_t *result) {
    if (!response || !payload || strlen(payload) == 0) {
        result->vulnerable = false;
        return false;
    }
    
    result->vulnerable = false;
    result->confidence = 0;
    result->reason = NULL;
    result->context = CTX_UNKNOWN;
    
    if (!strchr(payload, '<')) return false;
    
    if (!ci_strstr(response, payload)) return false;
    
    const char *new_tags[] = {
        "<a ", "<a>", "<div ", "<div>", "<span ", "<span>",
        "<p ", "<p>", "<b>", "<i>", "<u>", "<s>",
        "<h1", "<h2", "<h3", "<h4", "<h5", "<h6",
        "<table", "<tr", "<td", "<th", "<form", "<input",
        "<select", "<option", "<textarea", "<button",
        "<label", "<fieldset", "<legend", "<style", "<link",
        "<base", "<meta", "<title", "<noscript", "<template",
        NULL
    };
    
    for (int i = 0; new_tags[i]; i++) {
        if (ci_strstr(payload, new_tags[i])) {
            const char *events[] = {"onclick", "onmouseover", "onfocus", "onload", "onerror", NULL};
            for (int e = 0; events[e]; e++) {
                if (ci_strstr(payload, events[e])) {
                    result->vulnerable = true;
                    result->confidence = 93;
                    result->reason = "HTML tag with event handler";
                    result->context = CTX_HTML_TEXT;
                    return true;
                }
            }
            
            if (ci_strstr(payload, "href=javascript:") || ci_strstr(payload, "href=\"javascript:")) {
                result->vulnerable = true;
                result->confidence = 94;
                result->reason = "anchor with javascript URI";
                result->context = CTX_URL_CONTEXT;
                return true;
            }
        }
    }
    
    const char *dangerous_tags[] = {
        "<script", "<svg", "<img", "<iframe", "<object", "<embed",
        "<video", "<audio", "<body", "<math", "<details",
        NULL
    };
    
    for (int i = 0; dangerous_tags[i]; i++) {
        if (ci_strstr(payload, dangerous_tags[i])) {
            result->vulnerable = true;
            result->confidence = 96;
            result->reason = "dangerous tag injection";
            result->context = CTX_HTML_TEXT;
            return true;
        }
    }
    
    return false;
}
