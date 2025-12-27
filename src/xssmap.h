#ifndef XSSMAP_H
#define XSSMAP_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <pthread.h>
#include <curl/curl.h>

#define VERSION "1.0.0"
#define MAX_URL_LEN 4096
#define MAX_PAYLOAD_LEN 8192
#define MAX_RESPONSE_SIZE (1024 * 1024)
#define DEFAULT_THREADS 10
#define DEFAULT_TIMEOUT 10

typedef struct {
    char **urls;
    int url_count;
    char **payloads;
    int payload_count;
    int threads;
    int timeout;
    bool verbose;
    char *output_file;
} config_t;

typedef struct {
    char *data;
    size_t size;
} response_t;

typedef struct {
    int total_scanned;
    int total_found;
    char **vulnerable_urls;
    int vulnerable_count;
    pthread_mutex_t mutex;
} scan_result_t;

typedef struct {
    config_t *config;
    scan_result_t *result;
    int start_idx;
    int end_idx;
} thread_arg_t;

char **load_file_lines(const char *path, int *count);
void free_lines(char **lines, int count);
char *url_encode(const char *str);
char *inject_payload(const char *url, const char *payload);

response_t *http_get(const char *url, int timeout);
void free_response(response_t *resp);

void run_scan(config_t *config);
bool check_xss_reflection(const char *response, const char *payload);

#endif
