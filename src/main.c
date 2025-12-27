#include "xssmap.h"
#include <getopt.h>
#include <time.h>

static const char *user_agents[] = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
};

const char *get_random_ua(void) {
    return user_agents[rand() % 5];
}

static void print_help(void) {
    printf("\n");
    printf("\033[32m example:\033[0m\n");
    printf("    \033[36mxssmap\033[0m \033[90m-u http://target.com/page?q= -p payloads.txt\033[0m\n");
    printf("    \033[36mxssmap\033[0m \033[90m-l urls.txt -p payloads.txt -t 20\033[0m\n\n");
    printf("\033[32m options:\033[0m\n");
    printf("    \033[97m-u\033[0m      single URL to scan \033[91m(required)\033[0m\n");
    printf("    \033[97m-l\033[0m      file containing URLs\n");
    printf("    \033[97m-p\033[0m      payload file \033[91m(required)\033[0m\n");
    printf("    \033[97m-t\033[0m      number of threads \033[90m(default: 10)\033[0m\n");
    printf("    \033[97m-T\033[0m      request timeout in seconds \033[90m(default: 10)\033[0m\n");
    printf("    \033[97m-o\033[0m      output file for results\n");
    printf("    \033[97m-v\033[0m      verbose output\n");
    printf("    \033[97m-V\033[0m      show version\n");
    printf("    \033[97m-h\033[0m      show this help message\n\n");
    printf("\033[90m high-performance xss scanner - 10x faster than python\033[0m\n\n");
}

static void print_version(void) {
    printf("\n\033[36mxssmap\033[0m \033[90mv%s\033[0m\n\n", VERSION);
}

int main(int argc, char *argv[]) {
    srand(time(NULL));
    curl_global_init(CURL_GLOBAL_ALL);

    config_t config = {
        .urls = NULL,
        .url_count = 0,
        .payloads = NULL,
        .payload_count = 0,
        .threads = DEFAULT_THREADS,
        .timeout = DEFAULT_TIMEOUT,
        .verbose = false,
        .output_file = NULL,
    };

    char *single_url = NULL;
    char *url_file = NULL;
    char *payload_file = NULL;
    int opt;

    while ((opt = getopt(argc, argv, "u:l:p:t:T:o:vVh")) != -1) {
        switch (opt) {
            case 'u': single_url = optarg; break;
            case 'l': url_file = optarg; break;
            case 'p': payload_file = optarg; break;
            case 't': config.threads = atoi(optarg); break;
            case 'T': config.timeout = atoi(optarg); break;
            case 'o': config.output_file = optarg; break;
            case 'v': config.verbose = true; break;
            case 'V': print_version(); return 0;
            case 'h': print_help(); return 0;
            default: print_help(); return 1;
        }
    }

    if (!payload_file) {
        fprintf(stderr, "\033[91m[✗]\033[0m payload file required (-p)\n");
        print_help();
        return 1;
    }

    if (!single_url && !url_file) {
        fprintf(stderr, "\033[91m[✗]\033[0m URL required (-u or -l)\n");
        print_help();
        return 1;
    }

    config.payloads = load_file_lines(payload_file, &config.payload_count);
    if (!config.payloads || config.payload_count == 0) {
        fprintf(stderr, "\033[91m[✗]\033[0m failed to load payloads from %s\n", payload_file);
        return 1;
    }

    if (single_url) {
        if (strchr(single_url, '#')) {
            fprintf(stderr, "\033[33m[!]\033[0m URL contains fragment (#) - fragments are client-side only\n");
            fprintf(stderr, "    DOM-based XSS requires browser testing, not HTTP requests\n\n");
        }
        config.urls = malloc(sizeof(char *));
        config.urls[0] = strdup(single_url);
        config.url_count = 1;
    } else {
        config.urls = load_file_lines(url_file, &config.url_count);
        if (!config.urls || config.url_count == 0) {
            fprintf(stderr, "\033[91m[✗]\033[0m failed to load URLs from %s\n", url_file);
            free_lines(config.payloads, config.payload_count);
            return 1;
        }
    }

    if (config.threads < 1) config.threads = 1;
    if (config.threads > 100) config.threads = 100;

    printf("\n\033[36m[i]\033[0m loaded %d URLs, %d payloads, %d threads\n\n",
           config.url_count, config.payload_count, config.threads);

    run_scan(&config);

    free_lines(config.urls, config.url_count);
    free_lines(config.payloads, config.payload_count);
    curl_global_cleanup();

    return 0;
}
