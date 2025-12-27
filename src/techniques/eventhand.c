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

static const char *all_events[] = {
    "onabort", "onafterprint", "onanimationend", "onanimationiteration",
    "onanimationstart", "onauxclick", "onbeforecopy", "onbeforecut",
    "onbeforeinput", "onbeforepaste", "onbeforeprint", "onbeforeunload",
    "onblur", "oncancel", "oncanplay", "oncanplaythrough", "onchange",
    "onclick", "onclose", "oncontextmenu", "oncopy", "oncuechange",
    "oncut", "ondblclick", "ondrag", "ondragend", "ondragenter",
    "ondragleave", "ondragover", "ondragstart", "ondrop", "ondurationchange",
    "onemptied", "onended", "onerror", "onfocus", "onfocusin", "onfocusout",
    "onformdata", "ongotpointercapture", "onhashchange", "oninput",
    "oninvalid", "onkeydown", "onkeypress", "onkeyup", "onlanguagechange",
    "onload", "onloadeddata", "onloadedmetadata", "onloadstart",
    "onlostpointercapture", "onmessage", "onmessageerror", "onmousedown",
    "onmouseenter", "onmouseleave", "onmousemove", "onmouseout",
    "onmouseover", "onmouseup", "onmousewheel", "onoffline", "ononline",
    "onpagehide", "onpageshow", "onpaste", "onpause", "onplay", "onplaying",
    "onpointercancel", "onpointerdown", "onpointerenter", "onpointerleave",
    "onpointermove", "onpointerout", "onpointerover", "onpointerup",
    "onpopstate", "onprogress", "onratechange", "onrejectionhandled",
    "onreset", "onresize", "onscroll", "onsearch", "onseeked", "onseeking",
    "onselect", "onselectionchange", "onselectstart", "onshow", "onstalled",
    "onstorage", "onsubmit", "onsuspend", "ontimeupdate", "ontoggle",
    "ontouchcancel", "ontouchend", "ontouchmove", "ontouchstart",
    "ontransitioncancel", "ontransitionend", "ontransitionrun",
        "ontransitionstart", "onunhandledrejection", "onunload", "onvolumechange",
        "onwaiting", "onwebkitanimationend", "onwebkitanimationiteration",
        "onwebkitanimationstart", "onwebkittransitionend", "onwheel",
        "onbegin", "onfinish", "onrepeat", "onstart",
        NULL
    };

bool technique_event_handler(const char *response, const char *payload, detection_result_t *result) {
    if (!response || !payload || strlen(payload) == 0) {
        result->vulnerable = false;
        return false;
    }
    
    result->vulnerable = false;
    result->confidence = 0;
    result->reason = NULL;
    result->context = CTX_UNKNOWN;
    
    for (int i = 0; all_events[i]; i++) {
        char pattern[128];
        snprintf(pattern, sizeof(pattern), "%s=", all_events[i]);
        
        if (ci_strstr(payload, pattern)) {
            const char *pos = ci_find(response, pattern);
            if (pos) {
                const char *pay_pos = ci_find(response, payload);
                if (pay_pos) {
                    const char *scan = pay_pos;
                    while (scan > response && *scan != '<' && *scan != '>') scan--;
                    
                    if (*scan == '<') {
                        result->vulnerable = true;
                        result->confidence = 95;
                        result->reason = "event handler injection";
                        result->context = CTX_SCRIPT_DATA;
                        return true;
                    }
                }
            }
        }
    }
    
    if ((ci_strstr(payload, "autofocus") || ci_strstr(payload, "accesskey")) &&
        ci_strstr(payload, "onfocus")) {
        if (ci_strstr(response, payload)) {
            result->vulnerable = true;
            result->confidence = 92;
            result->reason = "auto-trigger event handler";
            result->context = CTX_SCRIPT_DATA;
            return true;
        }
    }
    
    return false;
}
