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

bool technique_template_injection(const char *response, const char *payload, detection_result_t *result) {
    result->vulnerable = false;
    result->confidence = 0;
    result->reason = NULL;
    result->context = CTX_UNKNOWN;
    
    if (!response || !payload || strlen(payload) == 0) return false;
    
    bool has_template = (strstr(payload, "${") != NULL) || 
                        (strstr(payload, "{{") != NULL) ||
                        (strstr(payload, "<%") != NULL);
    if (!has_template) return false;
    
    if (!ci_strstr(response, payload)) return false;
    
    const char *pos = response;
    while ((pos = strcasestr(pos, "<script")) != NULL) {
        const char *end = strcasestr(pos, "</script");
        if (!end) break;
        
        const char *content_start = strchr(pos + 7, '>');
        if (!content_start || content_start >= end) {
            pos = end;
            continue;
        }
        content_start++;
        
        size_t len = end - content_start;
        
        for (size_t i = 0; i + 1 < len; i++) {
            if (content_start[i] == '`') {
                size_t template_start = i + 1;
                size_t depth = 0;
                size_t j = template_start;
                
                while (j < len) {
                    if (content_start[j] == '\\' && j + 1 < len) {
                        j += 2;
                        continue;
                    }
                    if (content_start[j] == '`' && depth == 0) {
                        size_t template_len = j - template_start;
                        char *template_content = malloc(template_len + 1);
                        if (template_content) {
                            memcpy(template_content, content_start + template_start, template_len);
                            template_content[template_len] = '\0';
                            
                            if (strstr(template_content, payload) && strstr(template_content, "${")) {
                                result->vulnerable = true;
                                result->confidence = 93;
                                result->context = CTX_SCRIPT_TEMPLATE;
                                result->reason = "payload in template literal with interpolation";
                                free(template_content);
                                return true;
                            }
                            free(template_content);
                        }
                        break;
                    }
                    if (content_start[j] == '$' && j + 1 < len && content_start[j + 1] == '{') {
                        depth++;
                        j += 2;
                        continue;
                    }
                    if (content_start[j] == '}' && depth > 0) {
                        depth--;
                    }
                    j++;
                }
                i = j;
            }
        }
        pos = end;
    }
    
    if (strstr(response, payload) && strstr(payload, "{{")) {
        const char *angular_markers[] = {"ng-app", "ng-controller", "v-", "x-", NULL};
        for (int i = 0; angular_markers[i]; i++) {
            if (ci_strstr(response, angular_markers[i])) {
                result->vulnerable = true;
                result->confidence = 91;
                result->context = CTX_HTML_TEXT;
                result->reason = "Angular/Vue template injection";
                return true;
            }
        }
    }
    
    return false;
}

bool technique_csp_bypass(const char *response, const char *payload, detection_result_t *result) {
    result->vulnerable = false;
    result->confidence = 0;
    result->reason = NULL;
    result->context = CTX_UNKNOWN;
    
    if (!response || !payload || strlen(payload) == 0) return false;
    
    const char *bypass_patterns[] = {
        "<base href=",
        "<link rel=\"import\"",
        "<meta http-equiv=\"refresh\"",
        "require(",
        "import(",
        NULL
    };
    
    bool has_bypass = false;
    for (int i = 0; bypass_patterns[i]; i++) {
        if (ci_strstr(payload, bypass_patterns[i])) {
            has_bypass = true;
            break;
        }
    }
    if (!has_bypass) return false;
    
    if (!ci_strstr(response, payload)) return false;
    
    if (ci_strstr(response, "<base") && ci_strstr(payload, "<base")) {
        const char *base_pos = strcasestr(response, "<base");
        if (base_pos && !strcasestr(response, "<!--")) {
            const char *href = strcasestr(base_pos, "href=");
            if (href && href < base_pos + 100) {
                result->vulnerable = true;
                result->confidence = 89;
                result->context = CTX_HTML_TEXT;
                result->reason = "base tag injection (CSP bypass)";
                return true;
            }
        }
    }
    
    if (ci_strstr(response, "<meta") && ci_strstr(payload, "<meta")) {
        const char *meta_pos = strcasestr(response, "<meta");
        if (meta_pos) {
            const char *refresh = strcasestr(meta_pos, "http-equiv=\"refresh\"");
            if (!refresh) refresh = strcasestr(meta_pos, "http-equiv='refresh'");
            if (refresh && refresh < meta_pos + 150) {
                result->vulnerable = true;
                result->confidence = 87;
                result->context = CTX_HTML_TEXT;
                result->reason = "meta refresh injection";
                return true;
            }
        }
    }
    
    return false;
}

bool technique_dom_clobbering(const char *response, const char *payload, detection_result_t *result) {
    result->vulnerable = false;
    result->confidence = 0;
    result->reason = NULL;
    result->context = CTX_UNKNOWN;
    
    if (!response || !payload || strlen(payload) == 0) return false;
    
    bool has_clobber = ci_strstr(payload, "id=") || ci_strstr(payload, "name=");
    if (!has_clobber) return false;
    
    const char *clobber_targets[] = {
        "id=\"location\"", "id='location'",
        "id=\"document\"", "id='document'",
        "id=\"window\"", "id='window'",
        "name=\"location\"", "name='location'",
        "id=\"innerHTML\"", "name=\"innerHTML\"",
        "id=\"src\"", "name=\"src\"",
        "id=\"href\"", "name=\"href\"",
        NULL
    };
    
    for (int i = 0; clobber_targets[i]; i++) {
        if (ci_strstr(payload, clobber_targets[i]) && ci_strstr(response, clobber_targets[i])) {
            result->vulnerable = true;
            result->confidence = 85;
            result->context = CTX_HTML_TEXT;
            result->reason = "DOM clobbering injection";
            return true;
        }
    }
    
    if (ci_strstr(response, "<form") && ci_strstr(payload, "<form") &&
        (ci_strstr(payload, "id=") || ci_strstr(payload, "name="))) {
        result->vulnerable = true;
        result->confidence = 82;
        result->context = CTX_HTML_TEXT;
        result->reason = "form-based DOM clobbering";
        return true;
    }
    
    return false;
}

bool technique_mutation_xss(const char *response, const char *payload, detection_result_t *result) {
    result->vulnerable = false;
    result->confidence = 0;
    result->reason = NULL;
    result->context = CTX_UNKNOWN;
    
    if (!response || !payload || strlen(payload) == 0) return false;
    
    const char *mutation_patterns[] = {
        "<noscript><p title=\"</noscript><script>",
        "<table><colgroup><col style=\"</colgroup>",
        "<style><a style=\"</style><script>",
        "<title><style></title><script>",
        "<textarea></textarea><script>",
        "</select><script>",
        NULL
    };
    
    for (int i = 0; mutation_patterns[i]; i++) {
        if (ci_strstr(payload, mutation_patterns[i]) && ci_strstr(response, payload)) {
            result->vulnerable = true;
            result->confidence = 90;
            result->context = CTX_HTML_TEXT;
            result->reason = "mutation XSS pattern detected";
            return true;
        }
    }
    
    return false;
}
