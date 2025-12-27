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

static const char *popup_functions[] = {
    "alert(", "confirm(", "prompt(", "console.log(", "console.error(",
    "console.warn(", "console.info(", "eval(", "Function(", "setTimeout(",
    "setInterval(", "document.write(", "document.writeln(",
    NULL
};

static bool find_popup_in_script(const char *script_content, size_t len, const char *payload) {
    size_t pay_len = strlen(payload);
    
    for (int i = 0; popup_functions[i]; i++) {
        const char *func = popup_functions[i];
        size_t func_len = strlen(func);
        
        for (size_t j = 0; j + func_len <= len; j++) {
            bool found = true;
            for (size_t k = 0; k < func_len && found; k++) {
                if (tolower((unsigned char)script_content[j + k]) != tolower((unsigned char)func[k]))
                    found = false;
            }
            
            if (found) {
                size_t start = j + func_len;
                int depth = 1;
                size_t end = start;
                
                while (end < len && depth > 0) {
                    if (script_content[end] == '(') depth++;
                    else if (script_content[end] == ')') depth--;
                    end++;
                }
                
                if (depth == 0 && (end - start) < 512) {
                    char *func_arg = malloc(end - start + 1);
                    if (func_arg) {
                        memcpy(func_arg, script_content + start, end - start - 1);
                        func_arg[end - start - 1] = '\0';
                        
                        if (ci_strstr(func_arg, payload) || 
                            (pay_len <= end - start && strstr(func_arg, payload))) {
                            free(func_arg);
                            return true;
                        }
                        free(func_arg);
                    }
                }
            }
        }
    }
    return false;
}

static bool find_script_blocks(const char *html, const char *payload) {
    const char *pos = html;
    
    while ((pos = strcasestr(pos, "<script")) != NULL) {
        const char *script_end = strcasestr(pos, "</script");
        if (!script_end) break;
        
        const char *content_start = strchr(pos + 7, '>');
        if (!content_start || content_start >= script_end) {
            pos = script_end;
            continue;
        }
        content_start++;
        
        size_t content_len = script_end - content_start;
        if (content_len > 0 && find_popup_in_script(content_start, content_len, payload)) {
            return true;
        }
        
        pos = script_end;
    }
    
    return false;
}

static bool find_event_popup(const char *html, const char *payload) {
    const char *events[] = {
        "onclick=", "onerror=", "onload=", "onmouseover=", "onfocus=",
        "onblur=", "onmouseout=", "onchange=", "onsubmit=", "onkeydown=",
        "onkeyup=", "onkeypress=", "ondblclick=", "onmousedown=", "onmouseup=",
        "oninput=", "onscroll=", "onwheel=", "ondrag=", "ondrop=",
        "onpaste=", "oncopy=", "oncut=", "onbeforeunload=", "onhashchange=",
        "onpopstate=", "ontouchstart=", "ontouchmove=", "ontouchend=",
        "onanimationend=", "ontransitionend=", "onresize=",
        NULL
    };
    
    for (int i = 0; events[i]; i++) {
        const char *pos = html;
        while ((pos = strcasestr(pos, events[i])) != NULL) {
            pos += strlen(events[i]);
            
            char quote = 0;
            if (*pos == '"' || *pos == '\'') {
                quote = *pos++;
            }
            
            const char *end;
            if (quote) {
                end = strchr(pos, quote);
            } else {
                end = pos;
                while (*end && !isspace((unsigned char)*end) && *end != '>') end++;
            }
            
            if (end && end > pos) {
                size_t len = end - pos;
                if (len < 1024 && find_popup_in_script(pos, len, payload)) {
                    return true;
                }
            }
            
            if (!end) break;
            pos = end;
        }
    }
    
    return false;
}

static bool find_uri_popup(const char *html, const char *payload) {
    const char *url_attrs[] = {"href=", "src=", "action=", "formaction=", "data=", NULL};
    const char *dangerous_schemes[] = {"javascript:", NULL};
    
    for (int u = 0; url_attrs[u]; u++) {
        const char *pos = html;
        while ((pos = strcasestr(pos, url_attrs[u])) != NULL) {
            pos += strlen(url_attrs[u]);
            
            char quote = 0;
            if (*pos == '"' || *pos == '\'') {
                quote = *pos++;
            }
            
            for (int s = 0; dangerous_schemes[s]; s++) {
                size_t scheme_len = strlen(dangerous_schemes[s]);
                if (strncasecmp(pos, dangerous_schemes[s], scheme_len) == 0) {
                    const char *js_content = pos + scheme_len;
                    
                    const char *end;
                    if (quote) {
                        end = strchr(js_content, quote);
                    } else {
                        end = js_content;
                        while (*end && !isspace((unsigned char)*end) && *end != '>') end++;
                    }
                    
                    if (end && end > js_content) {
                        size_t len = end - js_content;
                        if (len < 1024 && find_popup_in_script(js_content, len, payload)) {
                            return true;
                        }
                    }
                    break;
                }
            }
            
            if (quote) {
                const char *next = strchr(pos, quote);
                if (next) pos = next + 1;
                else break;
            }
        }
    }
    
    return false;
}

bool technique_popup_detection(const char *response, const char *payload, detection_result_t *result) {
    result->vulnerable = false;
    result->confidence = 0;
    result->reason = NULL;
    result->context = CTX_UNKNOWN;
    
    if (!response || !payload || strlen(payload) == 0) return false;
    
    bool has_popup_call = false;
    for (int i = 0; popup_functions[i]; i++) {
        if (ci_strstr(payload, popup_functions[i])) {
            has_popup_call = true;
            break;
        }
    }
    if (!has_popup_call) return false;
    
    if (!ci_strstr(response, payload)) return false;
    
    if (find_script_blocks(response, payload)) {
        result->vulnerable = true;
        result->confidence = 97;
        result->context = CTX_SCRIPT_DATA;
        result->reason = "popup/eval function in script block";
        return true;
    }
    
    if (find_event_popup(response, payload)) {
        result->vulnerable = true;
        result->confidence = 96;
        result->context = CTX_SCRIPT_DATA;
        result->reason = "popup/eval function in event handler";
        return true;
    }
    
    if (find_uri_popup(response, payload)) {
        result->vulnerable = true;
        result->confidence = 95;
        result->context = CTX_URL_CONTEXT;
        result->reason = "popup/eval function in javascript: URI";
        return true;
    }
    
    return false;
}
