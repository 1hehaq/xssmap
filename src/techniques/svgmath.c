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

static const char *svg_tags[] = {
    "<svg", "<animate", "<set", "<animatetransform", "<animatemotion",
    "<use", "<foreignobject", "<image", NULL
};

static const char *math_tags[] = {
    "<math", "<maction", "<annotation-xml", NULL
};

static const char *iframe_tags[] = {
    "<iframe", "<frame", "<embed", "<object", "<applet", NULL
};

static bool is_in_safe_ctx(const char *html, const char *match_pos) {
    size_t offset = match_pos - html;
    bool in_comment = false;
    bool in_noscript = false;
    
    for (size_t i = 0; i < offset && i + 3 < offset; i++) {
        if (strncmp(html + i, "<!--", 4) == 0) {
            in_comment = true;
            i += 3;
            continue;
        }
        if (in_comment && strncmp(html + i, "-->", 3) == 0) {
            in_comment = false;
            i += 2;
            continue;
        }
        if (strncasecmp(html + i, "<noscript", 9) == 0) {
            in_noscript = true;
        }
        if (in_noscript && strncasecmp(html + i, "</noscript", 10) == 0) {
            in_noscript = false;
        }
    }
    
    return in_comment || in_noscript;
}

static bool check_svg_events(const char *svg_content, size_t len) {
    const char *events[] = {
        "onload=", "onerror=", "onbegin=", "onend=", "onrepeat=",
        "onmouseover=", "onclick=", "onfocus=", NULL
    };
    
    for (int i = 0; events[i]; i++) {
        for (size_t j = 0; j + strlen(events[i]) <= len; j++) {
            if (strncasecmp(svg_content + j, events[i], strlen(events[i])) == 0) {
                return true;
            }
        }
    }
    return false;
}

bool technique_svg_injection(const char *response, const char *payload, detection_result_t *result) {
    result->vulnerable = false;
    result->confidence = 0;
    result->reason = NULL;
    result->context = CTX_UNKNOWN;
    
    if (!response || !payload || strlen(payload) == 0) return false;
    
    bool has_svg = false;
    for (int i = 0; svg_tags[i]; i++) {
        if (ci_strstr(payload, svg_tags[i])) {
            has_svg = true;
            break;
        }
    }
    if (!has_svg) return false;
    
    for (int i = 0; svg_tags[i]; i++) {
        const char *pos = response;
        size_t tag_len = strlen(svg_tags[i]);
        
        while ((pos = strcasestr(pos, svg_tags[i])) != NULL) {
            if (is_in_safe_ctx(response, pos)) {
                pos += tag_len;
                continue;
            }
            
            const char *end = strchr(pos, '>');
            if (end) {
                size_t content_len = end - pos;
                
                if (ci_strstr(payload, svg_tags[i]) && strstr(pos, payload)) {
                    if (check_svg_events(pos, content_len) || 
                        ci_strstr(pos, "xlink:href=") ||
                        ci_strstr(pos, "href=")) {
                        result->vulnerable = true;
                        result->confidence = 94;
                        result->context = CTX_HTML_TEXT;
                        result->reason = "SVG element injection with events/links";
                        return true;
                    }
                    
                    result->vulnerable = true;
                    result->confidence = 88;
                    result->context = CTX_HTML_TEXT;
                    result->reason = "SVG element injection";
                    return true;
                }
            }
            pos += tag_len;
        }
    }
    
    return false;
}

bool technique_math_injection(const char *response, const char *payload, detection_result_t *result) {
    result->vulnerable = false;
    result->confidence = 0;
    result->reason = NULL;
    result->context = CTX_UNKNOWN;
    
    if (!response || !payload || strlen(payload) == 0) return false;
    
    bool has_math = false;
    for (int i = 0; math_tags[i]; i++) {
        if (ci_strstr(payload, math_tags[i])) {
            has_math = true;
            break;
        }
    }
    if (!has_math) return false;
    
    for (int i = 0; math_tags[i]; i++) {
        const char *pos = response;
        size_t tag_len = strlen(math_tags[i]);
        
        while ((pos = strcasestr(pos, math_tags[i])) != NULL) {
            if (is_in_safe_ctx(response, pos)) {
                pos += tag_len;
                continue;
            }
            
            if (ci_strstr(payload, math_tags[i])) {
                const char *end = strchr(pos, '>');
                if (end) {
                    size_t content_len = end - pos;
                    
                    if (ci_strstr(pos, "xlink:href=") || 
                        ci_strstr(pos, "href=") ||
                        ci_strstr(pos, "actiontype=")) {
                        result->vulnerable = true;
                        result->confidence = 92;
                        result->context = CTX_HTML_TEXT;
                        result->reason = "MathML injection with dangerous attributes";
                        return true;
                    }
                    
                    const char *script_in_math = strcasestr(pos, "<script");
                    if (script_in_math && script_in_math < pos + content_len + 200) {
                        result->vulnerable = true;
                        result->confidence = 95;
                        result->context = CTX_HTML_TEXT;
                        result->reason = "MathML with embedded script";
                        return true;
                    }
                }
            }
            pos += tag_len;
        }
    }
    
    return false;
}

bool technique_iframe_injection(const char *response, const char *payload, detection_result_t *result) {
    result->vulnerable = false;
    result->confidence = 0;
    result->reason = NULL;
    result->context = CTX_UNKNOWN;
    
    if (!response || !payload || strlen(payload) == 0) return false;
    
    bool has_iframe = false;
    for (int i = 0; iframe_tags[i]; i++) {
        if (ci_strstr(payload, iframe_tags[i])) {
            has_iframe = true;
            break;
        }
    }
    if (!has_iframe) return false;
    
    if (!ci_strstr(response, payload)) return false;
    
    for (int i = 0; iframe_tags[i]; i++) {
        const char *pos = response;
        size_t tag_len = strlen(iframe_tags[i]);
        
        while ((pos = strcasestr(pos, iframe_tags[i])) != NULL) {
            if (is_in_safe_ctx(response, pos)) {
                pos += tag_len;
                continue;
            }
            
            const char *end = strchr(pos, '>');
            if (end) {
                size_t content_len = end - pos;
                char *tag_content = malloc(content_len + 1);
                if (tag_content) {
                    memcpy(tag_content, pos, content_len);
                    tag_content[content_len] = '\0';
                    
                    if (ci_strstr(tag_content, "src=") || 
                        ci_strstr(tag_content, "srcdoc=") ||
                        ci_strstr(tag_content, "data=")) {
                        
                        if (ci_strstr(tag_content, "javascript:") ||
                            ci_strstr(tag_content, "data:text/html") ||
                            ci_strstr(tag_content, "srcdoc=")) {
                            result->vulnerable = true;
                            result->confidence = 96;
                            result->context = CTX_HTML_TEXT;
                            result->reason = "iframe/embed injection with dangerous src";
                            free(tag_content);
                            return true;
                        }
                        
                        result->vulnerable = true;
                        result->confidence = 85;
                        result->context = CTX_HTML_TEXT;
                        result->reason = "iframe/embed injection";
                        free(tag_content);
                        return true;
                    }
                    free(tag_content);
                }
            }
            pos += tag_len;
        }
    }
    
    return false;
}
