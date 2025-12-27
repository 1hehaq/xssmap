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

static bool is_in_safe_context(const char *response, const char *payload) {
    const char *pos = strstr(response, payload);
    if (!pos) {
        size_t resp_len = strlen(response);
        size_t pay_len = strlen(payload);
        char *resp_lower = malloc(resp_len + 1);
        char *pay_lower = malloc(pay_len + 1);
        
        for (size_t i = 0; i <= resp_len; i++)
            resp_lower[i] = tolower((unsigned char)response[i]);
        for (size_t i = 0; i <= pay_len; i++)
            pay_lower[i] = tolower((unsigned char)payload[i]);
        
        pos = strstr(resp_lower, pay_lower);
        if (pos) pos = response + (pos - resp_lower);
        
        free(resp_lower);
        free(pay_lower);
    }
    
    if (!pos) return true;
    
    size_t offset = pos - response;
    bool in_comment = false;
    bool in_noscript = false;
    bool in_style = false;
    bool in_cdata = false;
    bool in_textarea = false;
    bool in_title = false;
    
    for (size_t i = 0; i < offset; i++) {
        if (i + 3 < offset && strncmp(response + i, "<!--", 4) == 0) {
            in_comment = true;
            i += 3;
            continue;
        }
        if (in_comment && i + 2 < offset && strncmp(response + i, "-->", 3) == 0) {
            in_comment = false;
            i += 2;
            continue;
        }
        
        if (i + 8 < offset && strncasecmp(response + i, "<![CDATA[", 9) == 0) {
            in_cdata = true;
            i += 8;
            continue;
        }
        if (in_cdata && i + 2 < offset && strncmp(response + i, "]]>", 3) == 0) {
            in_cdata = false;
            i += 2;
            continue;
        }
        
        if (i + 9 < offset && strncasecmp(response + i, "<noscript", 9) == 0) {
            in_noscript = true;
        }
        if (in_noscript && i + 10 < offset && strncasecmp(response + i, "</noscript", 10) == 0) {
            in_noscript = false;
        }
        
        if (i + 6 < offset && strncasecmp(response + i, "<style", 6) == 0) {
            char next = response[i + 6];
            if (next == '>' || next == ' ' || next == '\t' || next == '\n') {
                in_style = true;
            }
        }
        if (in_style && i + 7 < offset && strncasecmp(response + i, "</style", 7) == 0) {
            in_style = false;
        }
        
        if (i + 9 < offset && strncasecmp(response + i, "<textarea", 9) == 0) {
            char next = response[i + 9];
            if (next == '>' || next == ' ' || next == '\t' || next == '\n') {
                in_textarea = true;
            }
        }
        if (in_textarea && i + 10 < offset && strncasecmp(response + i, "</textarea", 10) == 0) {
            in_textarea = false;
        }
        
        if (i + 6 < offset && strncasecmp(response + i, "<title", 6) == 0) {
            char next = response[i + 6];
            if (next == '>' || next == ' ' || next == '\t' || next == '\n') {
                in_title = true;
            }
        }
        if (in_title && i + 7 < offset && strncasecmp(response + i, "</title", 7) == 0) {
            in_title = false;
        }
    }
    
    return in_comment || in_noscript || in_cdata || in_style || in_textarea || in_title;
}

static bool has_executable_pattern(const char *payload) {
    const char *patterns[] = {
        "<script", "onerror=", "onload=", "onclick=", "onmouseover=",
        "onfocus=", "javascript:", "vbscript:", "<svg", "<img",
        "<iframe", "<body", "<input", "expression(", "eval(",
        "alert(", "confirm(", "prompt(", "document.", "window.",
        "<math", "<embed", "<object", "<frame", "console.",
        "setTimeout(", "setInterval(", "Function(", "<base",
        "<meta", "srcdoc=", "${", "{{", "<%",
        NULL
    };
    
    for (int i = 0; patterns[i]; i++) {
        if (ci_strstr(payload, patterns[i])) return true;
    }
    return false;
}

bool run_all_techniques(const char *response, const char *payload, detection_result_t *result) {
    if (!response || !payload || strlen(payload) == 0) {
        result->vulnerable = false;
        result->confidence = 0;
        result->reason = NULL;
        result->context = CTX_UNKNOWN;
        return false;
    }
    
    result->vulnerable = false;
    result->confidence = 0;
    result->reason = NULL;
    result->context = CTX_UNKNOWN;
    
    if (!has_executable_pattern(payload)) {
        return false;
    }
    
    if (!ci_strstr(response, payload)) {
        return false;
    }
    
    if (is_in_safe_context(response, payload)) {
        return false;
    }
    
    detection_result_t temp = {0};
    
    if (technique_popup_detection(response, payload, &temp) && temp.vulnerable) {
        *result = temp;
        return true;
    }
    
    if (technique_script_injection(response, payload, &temp) && temp.vulnerable) {
        *result = temp;
        return true;
    }
    
    if (technique_event_handler(response, payload, &temp) && temp.vulnerable) {
        *result = temp;
        return true;
    }
    
    if (technique_uri_injection(response, payload, &temp) && temp.vulnerable) {
        *result = temp;
        return true;
    }
    
    if (technique_svg_injection(response, payload, &temp) && temp.vulnerable) {
        *result = temp;
        return true;
    }
    
    if (technique_math_injection(response, payload, &temp) && temp.vulnerable) {
        *result = temp;
        return true;
    }
    
    if (technique_iframe_injection(response, payload, &temp) && temp.vulnerable) {
        *result = temp;
        return true;
    }
    
    if (technique_template_injection(response, payload, &temp) && temp.vulnerable) {
        *result = temp;
        return true;
    }
    
    if (technique_mutation_xss(response, payload, &temp) && temp.vulnerable) {
        *result = temp;
        return true;
    }
    
    if (technique_csp_bypass(response, payload, &temp) && temp.vulnerable) {
        *result = temp;
        return true;
    }
    
    if (technique_dom_clobbering(response, payload, &temp) && temp.vulnerable) {
        *result = temp;
        return true;
    }
    
    if (technique_tag_injection(response, payload, &temp) && temp.vulnerable) {
        *result = temp;
        return true;
    }
    
    if (technique_attribute_breakout(response, payload, &temp) && temp.vulnerable) {
        *result = temp;
        return true;
    }
    
    if (technique_dom_breakout(response, payload, &temp) && temp.vulnerable) {
        *result = temp;
        return true;
    }
    
    static __thread dom_parser_t parser = {0};
    static __thread bool parser_ready = false;
    
    if (!parser_ready) {
        parser_ready = dom_parser_init(&parser);
    }
    
    if (parser_ready) {
        if (dom_verify_xss(&parser, response, payload, &temp) && temp.vulnerable) {
            *result = temp;
            return true;
        }
    }
    
    return false;
}
