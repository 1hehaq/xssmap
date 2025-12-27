#include "xssmap.h"
#include <ctype.h>

char **load_file_lines(const char *path, int *count) {
    FILE *f = fopen(path, "r");
    if (!f) return NULL;

    int capacity = 1024;
    char **lines = malloc(capacity * sizeof(char *));
    *count = 0;

    char buf[MAX_PAYLOAD_LEN];
    while (fgets(buf, sizeof(buf), f)) {
        size_t len = strlen(buf);
        while (len > 0 && (buf[len-1] == '\n' || buf[len-1] == '\r'))
            buf[--len] = '\0';
        if (len == 0) continue;

        if (*count >= capacity) {
            capacity *= 2;
            lines = realloc(lines, capacity * sizeof(char *));
        }
        lines[(*count)++] = strdup(buf);
    }
    fclose(f);
    return lines;
}

void free_lines(char **lines, int count) {
    if (!lines) return;
    for (int i = 0; i < count; i++)
        free(lines[i]);
    free(lines);
}

char *url_encode(const char *str) {
    size_t len = strlen(str);
    char *enc = malloc(len * 3 + 1);
    char *p = enc;

    for (size_t i = 0; i < len; i++) {
        unsigned char c = str[i];
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~' ||
            c == '/' || c == '?' || c == '=' || c == '&' || c == ':' || c == '%') {
            *p++ = c;
        } else {
            sprintf(p, "%%%02X", c);
            p += 3;
        }
    }
    *p = '\0';
    return enc;
}

char *inject_payload(const char *url, const char *payload) {
    size_t url_len = strlen(url);
    size_t pay_len = strlen(payload);
    
    char *hash = strchr(url, '#');
    
    if (hash) {
        size_t base_len = hash - url;
        char *result = malloc(base_len + pay_len + url_len - base_len + 1);
        strncpy(result, url, base_len);
        strcpy(result + base_len, payload);
        strcat(result, hash);
        return result;
    }
    
    char *result = malloc(url_len + pay_len + 1);
    strcpy(result, url);
    strcat(result, payload);
    return result;
}

bool check_xss_reflection(const char *response, const char *payload) {
    (void)response;
    (void)payload;
    return false;
}
