#ifndef TECHNIQUES_H
#define TECHNIQUES_H

#include <stdbool.h>
#include <stddef.h>

typedef enum {
    CTX_UNKNOWN = 0,
    CTX_HTML_TEXT,
    CTX_HTML_COMMENT,
    CTX_TAG_NAME,
    CTX_ATTR_NAME,
    CTX_ATTR_VALUE_UNQUOTED,
    CTX_ATTR_VALUE_SINGLE,
    CTX_ATTR_VALUE_DOUBLE,
    CTX_SCRIPT_DATA,
    CTX_SCRIPT_STRING_SINGLE,
    CTX_SCRIPT_STRING_DOUBLE,
    CTX_SCRIPT_TEMPLATE,
    CTX_STYLE_DATA,
    CTX_URL_CONTEXT,
    CTX_NOSCRIPT,
    CTX_CDATA,
} html_context_t;

typedef struct {
    bool vulnerable;
    html_context_t context;
    const char *reason;
    int confidence;
} detection_result_t;

typedef struct {
    void *document;
    bool initialized;
} dom_parser_t;

bool dom_parser_init(dom_parser_t *parser);
void dom_parser_destroy(dom_parser_t *parser);
bool dom_parser_parse(dom_parser_t *parser, const char *html, size_t len);
html_context_t dom_get_context_at(dom_parser_t *parser, const char *html, const char *payload);
bool dom_verify_xss(dom_parser_t *parser, const char *html, const char *payload, detection_result_t *result);

bool technique_script_injection(const char *response, const char *payload, detection_result_t *result);
bool technique_event_handler(const char *response, const char *payload, detection_result_t *result);
bool technique_attribute_breakout(const char *response, const char *payload, detection_result_t *result);
bool technique_tag_injection(const char *response, const char *payload, detection_result_t *result);
bool technique_uri_injection(const char *response, const char *payload, detection_result_t *result);
bool technique_dom_breakout(const char *response, const char *payload, detection_result_t *result);

bool technique_popup_detection(const char *response, const char *payload, detection_result_t *result);
bool technique_svg_injection(const char *response, const char *payload, detection_result_t *result);
bool technique_math_injection(const char *response, const char *payload, detection_result_t *result);
bool technique_iframe_injection(const char *response, const char *payload, detection_result_t *result);
bool technique_template_injection(const char *response, const char *payload, detection_result_t *result);
bool technique_csp_bypass(const char *response, const char *payload, detection_result_t *result);
bool technique_dom_clobbering(const char *response, const char *payload, detection_result_t *result);
bool technique_mutation_xss(const char *response, const char *payload, detection_result_t *result);

bool run_all_techniques(const char *response, const char *payload, detection_result_t *result);

#endif
