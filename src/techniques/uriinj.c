#include "techniques.h"
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdio.h>

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

static bool is_html_encoded(const char *response, const char *payload) {
    if (!response || !payload) return false;
    
    const char *pos = strstr(response, payload);
    if (!pos) return true;
    
    size_t offset = pos - response;
    bool in_style = false;
    bool in_meta = false;
    
    for (size_t i = 0; i < offset; i++) {
        if (i + 6 < offset && strncasecmp(response + i, "<style", 6) == 0) {
            char next = response[i + 6];
            if (next == '>' || next == ' ' || next == '\t' || next == '\n') {
                in_style = true;
            }
        }
        if (in_style && i + 7 < offset && strncasecmp(response + i, "</style", 7) == 0) {
            in_style = false;
        }
        
        if (i + 5 < offset && strncasecmp(response + i, "style=", 6) == 0) {
            in_style = true;
        }
        if (in_style && (response[i] == '>' || (response[i] == '"' && i > 0 && response[i-1] != '='))) {
            in_style = false;
        }
        
        if (i + 5 < offset && strncasecmp(response + i, "<meta", 5) == 0) {
            in_meta = true;
        }
        if (in_meta && response[i] == '>') {
            in_meta = false;
        }
    }
    
    if (in_style || in_meta) return true;
    
    if (strstr(response, "&quot;") && strstr(payload, "\"")) return true;
    if (strstr(response, "&lt;") && strstr(payload, "<")) return true;
    if (strstr(response, "&gt;") && strstr(payload, ">")) return true;
    if (strstr(response, "&#") && (strstr(payload, "javascript") || strstr(payload, "data:"))) return true;
    
    if (pos >= response + 6) {
        if (strncasecmp(pos - 6, "&quot;", 6) == 0) return true;
    }
    
    return false;
}

bool technique_uri_injection(const char *response, const char *payload, detection_result_t *result) {
    if (!response || !payload || strlen(payload) == 0) {
        result->vulnerable = false;
        return false;
    }
    
    result->vulnerable = false;
    result->confidence = 0;
    result->reason = NULL;
    result->context = CTX_UNKNOWN;
    
    const char *dangerous_protos[] = {
        "javascript:", "vbscript:", "data:text/html",
        "data:application/xhtml", "data:image/svg+xml",
        NULL
    };
    
    bool has_dangerous = false;
    for (int i = 0; dangerous_protos[i]; i++) {
        if (ci_strstr(payload, dangerous_protos[i])) {
            has_dangerous = true;
            break;
        }
    }
    
    if (!has_dangerous) return false;
    
    if (!ci_strstr(response, payload)) return false;
    
    if (is_html_encoded(response, payload)) return false;
    
    const char *url_contexts[] = {
        "href=", "src=", "action=", "formaction=", "data=",
        "poster=", "background=", "xlink:href=", "srcdoc=",
        "href =", "src =", "action =",
        NULL
    };
    
    for (int i = 0; url_contexts[i]; i++) {
        if (ci_strstr(response, url_contexts[i])) {
            char search[256];
            for (int q = 0; q < 3; q++) {
                const char *quote = (q == 0) ? "\"" : (q == 1) ? "'" : "";
                snprintf(search, sizeof(search), "%s%s%s", url_contexts[i], quote, payload);
                
                if (ci_strstr(response, search)) {
                    result->vulnerable = true;
                    result->confidence = 97;
                    result->reason = "javascript/data URI in URL attribute";
                    result->context = CTX_URL_CONTEXT;
                    return true;
                }
            }
        }
    }
    
    return false;
}
