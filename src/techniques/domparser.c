#include "techniques.h"
#include <lexbor/html/parser.h>
#include <lexbor/html/serialize.h>
#include <lexbor/dom/interfaces/element.h>
#include <lexbor/dom/interfaces/attr.h>
#include <lexbor/dom/collection.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

bool dom_parser_init(dom_parser_t *parser) {
    parser->document = lxb_html_document_create();
    parser->initialized = (parser->document != NULL);
    return parser->initialized;
}

void dom_parser_destroy(dom_parser_t *parser) {
    if (parser->document) {
        lxb_html_document_destroy(parser->document);
        parser->document = NULL;
    }
    parser->initialized = false;
}

bool dom_parser_parse(dom_parser_t *parser, const char *html, size_t len) {
    if (!parser->initialized || !parser->document) return false;
    
    lxb_status_t status = lxb_html_document_parse(
        (lxb_html_document_t *)parser->document,
        (const lxb_char_t *)html,
        len
    );
    
    return status == LXB_STATUS_OK;
}

typedef struct {
    const char *payload;
    size_t payload_len;
    html_context_t found_ctx;
    bool found;
    bool in_script_attr;
    bool in_dangerous_attr;
} search_ctx_t;

static bool ci_contains(const char *haystack, size_t h_len, const char *needle, size_t n_len) {
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

static bool is_event_attr(const char *attr, size_t len) {
    return len >= 2 && tolower(attr[0]) == 'o' && tolower(attr[1]) == 'n';
}

static bool is_url_attr(const char *attr, size_t len) {
    const char *url_attrs[] = {"href", "src", "action", "formaction", "data", "poster", 
                               "background", "xlink:href", "dynsrc", "lowsrc", NULL};
    for (int i = 0; url_attrs[i]; i++) {
        if (len == strlen(url_attrs[i]) && strncasecmp(attr, url_attrs[i], len) == 0)
            return true;
    }
    return false;
}

static lxb_status_t check_element_callback(lxb_dom_node_t *node, void *ctx) {
    search_ctx_t *search = (search_ctx_t *)ctx;
    
    if (node->type == LXB_DOM_NODE_TYPE_TEXT) {
        lxb_dom_text_t *text = lxb_dom_interface_text(node);
        size_t len;
        const lxb_char_t *content = lxb_dom_node_text_content(node, &len);
        
        if (content && ci_contains((const char *)content, len, search->payload, search->payload_len)) {
            lxb_dom_node_t *parent = node->parent;
            if (parent && parent->type == LXB_DOM_NODE_TYPE_ELEMENT) {
                lxb_dom_element_t *el = lxb_dom_interface_element(parent);
                const lxb_char_t *tag = lxb_dom_element_local_name(el, &len);
                
                if (tag && strncasecmp((const char *)tag, "script", len) == 0) {
                    search->found_ctx = CTX_SCRIPT_DATA;
                } else if (tag && strncasecmp((const char *)tag, "style", len) == 0) {
                    search->found_ctx = CTX_STYLE_DATA;
                } else if (tag && strncasecmp((const char *)tag, "noscript", len) == 0) {
                    search->found_ctx = CTX_NOSCRIPT;
                } else {
                    search->found_ctx = CTX_HTML_TEXT;
                }
            } else {
                search->found_ctx = CTX_HTML_TEXT;
            }
            search->found = true;
        }
    }
    else if (node->type == LXB_DOM_NODE_TYPE_ELEMENT) {
        lxb_dom_element_t *el = lxb_dom_interface_element(node);
        lxb_dom_attr_t *attr = lxb_dom_element_first_attribute(el);
        
        while (attr) {
            size_t name_len, value_len;
            const lxb_char_t *name = lxb_dom_attr_local_name(attr, &name_len);
            const lxb_char_t *value = lxb_dom_attr_value(attr, &value_len);
            
            if (value && ci_contains((const char *)value, value_len, search->payload, search->payload_len)) {
                if (name && is_event_attr((const char *)name, name_len)) {
                    search->found_ctx = CTX_SCRIPT_DATA;
                    search->in_script_attr = true;
                } else if (name && is_url_attr((const char *)name, name_len)) {
                    search->found_ctx = CTX_URL_CONTEXT;
                    search->in_dangerous_attr = true;
                } else {
                    search->found_ctx = CTX_ATTR_VALUE_DOUBLE;
                }
                search->found = true;
            }
            
            attr = lxb_dom_element_next_attribute(attr);
        }
    }
    else if (node->type == LXB_DOM_NODE_TYPE_COMMENT) {
        size_t len;
        const lxb_char_t *content = lxb_dom_node_text_content(node, &len);
        if (content && ci_contains((const char *)content, len, search->payload, search->payload_len)) {
            search->found_ctx = CTX_HTML_COMMENT;
            search->found = true;
        }
    }
    
    return LXB_STATUS_OK;
}

html_context_t dom_get_context_at(dom_parser_t *parser, const char *html, const char *payload) {
    if (!parser->initialized || !parser->document || !payload) return CTX_UNKNOWN;
    
    lxb_html_document_t *doc = (lxb_html_document_t *)parser->document;
    lxb_dom_node_t *root = lxb_dom_interface_node(doc);
    
    search_ctx_t search = {
        .payload = payload,
        .payload_len = strlen(payload),
        .found_ctx = CTX_UNKNOWN,
        .found = false,
        .in_script_attr = false,
        .in_dangerous_attr = false
    };
    
    lxb_dom_node_simple_walk(root, check_element_callback, &search);
    
    return search.found ? search.found_ctx : CTX_UNKNOWN;
}

static bool check_executable_script(lxb_html_document_t *doc, const char *payload, size_t pay_len) {
    lxb_dom_collection_t *col = lxb_dom_collection_make(&doc->dom_document, 16);
    if (!col) return false;
    
    lxb_dom_elements_by_tag_name(lxb_dom_interface_element(doc->body), col, 
                                  (const lxb_char_t *)"script", 6);
    
    bool found_in_script = false;
    for (size_t i = 0; i < lxb_dom_collection_length(col); i++) {
        lxb_dom_element_t *el = lxb_dom_collection_element(col, i);
        lxb_dom_node_t *child = lxb_dom_interface_node(el)->first_child;
        
        while (child) {
            if (child->type == LXB_DOM_NODE_TYPE_TEXT) {
                size_t len;
                const lxb_char_t *text = lxb_dom_node_text_content(child, &len);
                if (text && ci_contains((const char *)text, len, payload, pay_len)) {
                    found_in_script = true;
                    break;
                }
            }
            child = child->next;
        }
        if (found_in_script) break;
    }
    
    lxb_dom_collection_destroy(col, true);
    return found_in_script;
}

static bool check_event_handlers(lxb_html_document_t *doc, const char *payload, size_t pay_len) {
    const char *events[] = {
        "onclick", "onerror", "onload", "onmouseover", "onfocus", "onblur",
        "onchange", "onsubmit", "onkeydown", "onkeyup", "onmousedown",
        "onmouseup", "ondblclick", "oncontextmenu", "oninput", "onscroll",
        "onwheel", "ondrag", "ondrop", "onpaste", "oncopy", "oncut",
        "onanimationend", "ontransitionend", "onpopstate", "onhashchange",
        "onbeforeunload", "onunload", "onmessage", "onstorage", "onerror",
        NULL
    };
    
    lxb_dom_collection_t *col = lxb_dom_collection_make(&doc->dom_document, 128);
    if (!col) return false;
    
    lxb_dom_elements_by_tag_name(lxb_dom_interface_element(doc->body), col, 
                                  (const lxb_char_t *)"*", 1);
    
    bool found = false;
    for (size_t i = 0; i < lxb_dom_collection_length(col) && !found; i++) {
        lxb_dom_element_t *el = lxb_dom_collection_element(col, i);
        
        for (int e = 0; events[e] && !found; e++) {
            size_t val_len;
            const lxb_char_t *val = lxb_dom_element_get_attribute(
                el, (const lxb_char_t *)events[e], strlen(events[e]), &val_len
            );
            
            if (val && ci_contains((const char *)val, val_len, payload, pay_len)) {
                found = true;
            }
        }
    }
    
    lxb_dom_collection_destroy(col, true);
    return found;
}

static bool check_dangerous_urls(lxb_html_document_t *doc, const char *payload, size_t pay_len) {
    const char *url_attrs[] = {"href", "src", "action", "formaction", "data", "poster", NULL};
    const char *dangerous_protos[] = {"javascript:", "vbscript:", "data:text/html", NULL};
    
    bool has_dangerous_proto = false;
    for (int i = 0; dangerous_protos[i]; i++) {
        if (ci_contains(payload, pay_len, dangerous_protos[i], strlen(dangerous_protos[i]))) {
            has_dangerous_proto = true;
            break;
        }
    }
    if (!has_dangerous_proto) return false;
    
    lxb_dom_collection_t *col = lxb_dom_collection_make(&doc->dom_document, 128);
    if (!col) return false;
    
    lxb_dom_elements_by_tag_name(lxb_dom_interface_element(doc->body), col, 
                                  (const lxb_char_t *)"*", 1);
    
    bool found = false;
    for (size_t i = 0; i < lxb_dom_collection_length(col) && !found; i++) {
        lxb_dom_element_t *el = lxb_dom_collection_element(col, i);
        
        for (int a = 0; url_attrs[a] && !found; a++) {
            size_t val_len;
            const lxb_char_t *val = lxb_dom_element_get_attribute(
                el, (const lxb_char_t *)url_attrs[a], strlen(url_attrs[a]), &val_len
            );
            
            if (val && val_len > 0) {
                const char *sval = (const char *)val;
                if (sval[0] == '"' || sval[0] == '\'' || sval[0] == ' ') {
                    continue;
                }
                
                bool starts_with_dangerous = false;
                for (int p = 0; dangerous_protos[p]; p++) {
                    size_t proto_len = strlen(dangerous_protos[p]);
                    if (val_len >= proto_len && 
                        strncasecmp(sval, dangerous_protos[p], proto_len) == 0) {
                        starts_with_dangerous = true;
                        break;
                    }
                }
                
                if (starts_with_dangerous && ci_contains(sval, val_len, payload, pay_len)) {
                    found = true;
                }
            }
        }
    }
    
    lxb_dom_collection_destroy(col, true);
    return found;
}

bool dom_verify_xss(dom_parser_t *parser, const char *html, const char *payload, detection_result_t *result) {
    if (!parser || !html || !payload) {
        result->vulnerable = false;
        return false;
    }
    
    size_t html_len = strlen(html);
    size_t pay_len = strlen(payload);
    
    if (!parser->initialized) {
        if (!dom_parser_init(parser)) {
            result->vulnerable = false;
            return false;
        }
    }
    
    lxb_html_document_t *doc = (lxb_html_document_t *)parser->document;
    lxb_html_document_clean(doc);
    
    lxb_status_t status = lxb_html_document_parse(doc, (const lxb_char_t *)html, html_len);
    if (status != LXB_STATUS_OK) {
        result->vulnerable = false;
        return false;
    }
    
    result->vulnerable = false;
    result->confidence = 0;
    result->context = CTX_UNKNOWN;
    result->reason = NULL;
    
    if (check_executable_script(doc, payload, pay_len)) {
        result->vulnerable = true;
        result->confidence = 98;
        result->context = CTX_SCRIPT_DATA;
        result->reason = "payload in executable script context";
        return true;
    }
    
    if (check_event_handlers(doc, payload, pay_len)) {
        result->vulnerable = true;
        result->confidence = 95;
        result->context = CTX_SCRIPT_DATA;
        result->reason = "payload in event handler attribute";
        return true;
    }
    
    if (check_dangerous_urls(doc, payload, pay_len)) {
        result->vulnerable = true;
        result->confidence = 95;
        result->context = CTX_URL_CONTEXT;
        result->reason = "dangerous URI scheme in URL attribute";
        return true;
    }
    
    html_context_t ctx = dom_get_context_at(parser, html, payload);
    result->context = ctx;
    
    switch (ctx) {
        case CTX_HTML_TEXT:
            if (strchr(payload, '<') && strstr(html, payload)) {
                result->vulnerable = true;
                result->confidence = 90;
                result->reason = "unescaped HTML tag injection";
                return true;
            }
            break;
            
        case CTX_SCRIPT_DATA:
            result->vulnerable = true;
            result->confidence = 92;
            result->reason = "payload reflected in script context";
            return true;
            
        case CTX_HTML_COMMENT:
        case CTX_NOSCRIPT:
        case CTX_STYLE_DATA:
            result->vulnerable = false;
            result->confidence = 0;
            return false;
            
        default:
            break;
    }
    
    return false;
}
