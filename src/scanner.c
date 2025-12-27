#include "xssmap.h"
#include "techniques/techniques.h"
#include <time.h>

typedef struct {
    config_t *config;
    scan_result_t *result;
    int url_idx;
    int payload_start;
    int payload_end;
} task_t;

static void *scan_worker(void *arg) {
    task_t *task = (task_t *)arg;
    config_t *config = task->config;
    scan_result_t *result = task->result;
    
    const char *url = config->urls[task->url_idx];

    for (int i = task->payload_start; i < task->payload_end; i++) {
        const char *payload = config->payloads[i];
        char *test_url = inject_payload(url, payload);

        response_t *resp = http_get(test_url, config->timeout);

        pthread_mutex_lock(&result->mutex);
        result->total_scanned++;
        pthread_mutex_unlock(&result->mutex);

        bool vulnerable = false;
        detection_result_t det_result = {0};
        
        if (resp && resp->data && resp->size > 0) {
            vulnerable = run_all_techniques(resp->data, payload, &det_result);
        }

        if (vulnerable && det_result.confidence >= 70) {
            pthread_mutex_lock(&result->mutex);
            result->total_found++;
            result->vulnerable_urls = realloc(result->vulnerable_urls, 
                                              (result->vulnerable_count + 1) * sizeof(char *));
            result->vulnerable_urls[result->vulnerable_count++] = strdup(test_url);

            printf("\033[32m[✓]\033[0m %s\n", test_url);
            pthread_mutex_unlock(&result->mutex);
        } else if (config->verbose) {
            pthread_mutex_lock(&result->mutex);
            printf("\033[91m[✗]\033[0m \033[90m%s\033[0m\n", test_url);
            pthread_mutex_unlock(&result->mutex);
        }

        free_response(resp);
        free(test_url);
    }

    free(task);
    return NULL;
}

void run_scan(config_t *config) {
    time_t start_time = time(NULL);

    scan_result_t result = {
        .total_scanned = 0,
        .total_found = 0,
        .vulnerable_urls = NULL,
        .vulnerable_count = 0,
    };
    pthread_mutex_init(&result.mutex, NULL);

    int total_tasks = config->url_count * config->payload_count;
    int max_threads = config->threads;
    if (max_threads > total_tasks) max_threads = total_tasks;

    pthread_t *threads = malloc(max_threads * sizeof(pthread_t));
    int thread_count = 0;

    for (int u = 0; u < config->url_count; u++) {
        printf("\033[36m→\033[0m %s\n", config->urls[u]);

        int payloads_per_thread = config->payload_count / max_threads;
        int remainder = config->payload_count % max_threads;
        int start = 0;

        thread_count = 0;
        for (int t = 0; t < max_threads && start < config->payload_count; t++) {
            int batch = payloads_per_thread + (t < remainder ? 1 : 0);
            if (batch == 0) break;

            task_t *task = malloc(sizeof(task_t));
            task->config = config;
            task->result = &result;
            task->url_idx = u;
            task->payload_start = start;
            task->payload_end = start + batch;

            pthread_create(&threads[thread_count++], NULL, scan_worker, task);
            start += batch;
        }

        for (int t = 0; t < thread_count; t++) {
            pthread_join(threads[t], NULL);
        }
    }

    free(threads);

    time_t end_time = time(NULL);
    int elapsed = (int)(end_time - start_time);

    printf("\n\033[90mcompleted: %d/%d in %ds\033[0m\n", result.total_found, result.total_scanned, elapsed);

    if (config->output_file && result.vulnerable_count > 0) {
        FILE *f = fopen(config->output_file, "w");
        if (f) {
            for (int i = 0; i < result.vulnerable_count; i++) {
                fprintf(f, "%s\n", result.vulnerable_urls[i]);
            }
            fclose(f);
            printf("\033[32m[✓]\033[0m saved to %s\n", config->output_file);
        }
    }

    for (int i = 0; i < result.vulnerable_count; i++) {
        free(result.vulnerable_urls[i]);
    }
    free(result.vulnerable_urls);
    pthread_mutex_destroy(&result.mutex);
}
