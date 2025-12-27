#include "xssmap.h"

extern const char *get_random_ua(void);

static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    response_t *resp = (response_t *)userp;

    if (resp->size + realsize > MAX_RESPONSE_SIZE) {
        return 0;
    }

    char *ptr = realloc(resp->data, resp->size + realsize + 1);
    if (!ptr) return 0;

    resp->data = ptr;
    memcpy(&(resp->data[resp->size]), contents, realsize);
    resp->size += realsize;
    resp->data[resp->size] = '\0';

    return realsize;
}

response_t *http_get(const char *url, int timeout) {
    CURL *curl = curl_easy_init();
    if (!curl) return NULL;

    response_t *resp = malloc(sizeof(response_t));
    resp->data = malloc(1);
    resp->data[0] = '\0';
    resp->size = 0;

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
    headers = curl_slist_append(headers, "Accept-Language: en-US,en;q=0.5");
    headers = curl_slist_append(headers, "Connection: close");

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)resp);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, get_random_ua());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 3L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

    CURLcode res = curl_easy_perform(curl);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        free(resp->data);
        free(resp);
        return NULL;
    }

    return resp;
}

void free_response(response_t *resp) {
    if (resp) {
        free(resp->data);
        free(resp);
    }
}
