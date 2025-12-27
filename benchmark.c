#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdbool.h>
#include "src/techniques/techniques.h"

typedef struct {
    const char *name;
    const char *html;
    const char *payload;
    bool expected_vuln;
} test_case_t;

static test_case_t test_cases[] = {
    {"script_reflected_vuln", "<html><body><script>alert(1)</script></body></html>", "<script>alert(1)</script>", true},
    {"script_encoded_safe", "<html><body>&lt;script&gt;alert(1)&lt;/script&gt;</body></html>", "<script>alert(1)</script>", false},
    {"onerror_vuln", "<html><img src=x onerror=alert(1)></html>", "<img src=x onerror=alert(1)>", true},
    {"onerror_encoded_safe", "<html>&lt;img src=x onerror=alert(1)&gt;</html>", "<img src=x onerror=alert(1)>", false},
    {"attr_breakout_vuln", "<html><input value=\"\"><script>alert(1)</script>\"></html>", "\"><script>alert(1)</script>", true},
    {"attr_breakout_encoded", "<html><input value=\"&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;\"></html>", "\"><script>alert(1)</script>", false},
    {"svg_onload_vuln", "<html><svg onload=alert(1)></svg></html>", "<svg onload=alert(1)>", true},
    {"svg_encoded_safe", "<html>&lt;svg onload=alert(1)&gt;&lt;/svg&gt;</html>", "<svg onload=alert(1)>", false},
    {"javascript_uri_vuln", "<html><a href=\"javascript:alert(1)\">click</a></html>", "javascript:alert(1)", true},
    {"javascript_uri_safe", "<html><a href=\"&quot;javascript:alert(1)&quot;\">click</a></html>", "javascript:alert(1)", false},
    {"in_comment_safe", "<html><!-- <script>alert(1)</script> --></html>", "<script>alert(1)</script>", false},
    {"script_context_vuln", "<html><script>var x='';alert(1)//'';</script></html>", "';alert(1)//", true},
    {"data_uri_vuln", "<html><a href=\"data:text/html,<script>alert(1)</script>\">x</a></html>", "data:text/html,<script>alert(1)</script>", true},
    {"iframe_srcdoc_vuln", "<html><iframe srcdoc=\"<script>alert(1)</script>\"></iframe></html>", "<script>alert(1)</script>", true},
    {"style_expression_safe", "<html><div style=\"background:url(javascript:alert(1))\">x</div></html>", "javascript:alert(1)", false},
    {"noscript_safe", "<html><noscript><script>alert(1)</script></noscript></html>", "<script>alert(1)</script>", false},
    {"textarea_safe", "<html><textarea><script>alert(1)</script></textarea></html>", "<script>alert(1)</script>", false},
    {"title_safe", "<html><title><script>alert(1)</script></title></html>", "<script>alert(1)</script>", false},
    {"body_onload_vuln", "<html><body onload=alert(1)></body></html>", "<body onload=alert(1)>", true},
    {"img_onerror_vuln", "<html><img src=1 onerror=alert(1)></html>", "<img src=1 onerror=alert(1)>", true},
    {"details_ontoggle_vuln", "<html><details ontoggle=alert(1) open>x</details></html>", "<details ontoggle=alert(1) open>", true},
    {"marquee_onstart_vuln", "<html><marquee onstart=alert(1)>x</marquee></html>", "<marquee onstart=alert(1)>", true},
    {"video_onerror_vuln", "<html><video onerror=alert(1)><source src=x></video></html>", "<video onerror=alert(1)>", true},
    {"object_data_vuln", "<html><object data=\"javascript:alert(1)\"></object></html>", "javascript:alert(1)", true},
    {"embed_src_vuln", "<html><embed src=\"javascript:alert(1)\"></embed></html>", "javascript:alert(1)", true},
    {"base_href_vuln", "<html><base href=\"javascript:alert(1)//\"></html>", "javascript:alert(1)", true},
    {"form_action_vuln", "<html><form action=\"javascript:alert(1)\"><input type=submit></form></html>", "javascript:alert(1)", true},
    {"button_formaction_vuln", "<html><form><button formaction=\"javascript:alert(1)\">x</button></form></html>", "javascript:alert(1)", true},
    {"meta_refresh_safe", "<html><meta http-equiv=\"refresh\" content=\"0;url=javascript:alert(1)\"></html>", "javascript:alert(1)", false},
    {"cdata_safe", "<html><script>//<![CDATA[\nalert(1)\n//]]></script></html>", "alert(1)", false},
    {"double_encoded_safe", "<html>%3Cscript%3Ealert(1)%3C/script%3E</html>", "<script>alert(1)</script>", false},
    {"partial_script_safe", "<html><scr<script>ipt>alert(1)</script></html>", "<script>alert(1)</script>", false},
    {"uppercase_script_vuln", "<html><SCRIPT>alert(1)</SCRIPT></html>", "<SCRIPT>alert(1)</SCRIPT>", true},
    {"mixed_case_vuln", "<html><ScRiPt>alert(1)</ScRiPt></html>", "<ScRiPt>alert(1)</ScRiPt>", true},
    {"null_byte_vuln", "<html><scr\x00ipt>alert(1)</script></html>", "<script>alert(1)</script>", false},
    {"tab_inject_vuln", "<html><img\tsrc=x\tonerror=alert(1)></html>", "<img\tsrc=x\tonerror=alert(1)>", true},
    {"newline_inject_vuln", "<html><img\nsrc=x\nonerror=alert(1)></html>", "<img\nsrc=x\nonerror=alert(1)>", true},
    {"autofocus_vuln", "<html><input autofocus onfocus=alert(1)></html>", "<input autofocus onfocus=alert(1)>", true},
    {"svg_animate_vuln", "<html><svg><animate onbegin=alert(1)></svg></html>", "<svg><animate onbegin=alert(1)>", true},
    {"math_vuln", "<html><math><maction actiontype=\"statusline#\" xlink:href=\"javascript:alert(1)\">x</maction></math></html>", "javascript:alert(1)", true},
};

#define NUM_TESTS (sizeof(test_cases) / sizeof(test_cases[0]))

static void print_colored(const char *color, const char *text) {
    printf("%s%s\033[0m", color, text);
}

int main(int argc, char *argv[]) {
    printf("\n\033[36m╔══════════════════════════════════════════════════════════════╗\033[0m\n");
    printf("\033[36m║\033[0m        \033[1;97mXSSMAP BENCHMARK - Detection Accuracy Test\033[0m        \033[36m	║\033[0m\n");
    printf("\033[36m╚══════════════════════════════════════════════════════════════╝\033[0m\n\n");

    int tp = 0, tn = 0, fp = 0, fn = 0;
    int pass = 0, fail = 0;
    
    clock_t start = clock();

    for (size_t i = 0; i < NUM_TESTS; i++) {
        test_case_t *tc = &test_cases[i];
        detection_result_t result = {0};
        
        bool detected = run_all_techniques(tc->html, tc->payload, &result);
        bool correct = (detected == tc->expected_vuln);

        if (tc->expected_vuln && detected) tp++;
        else if (!tc->expected_vuln && !detected) tn++;
        else if (!tc->expected_vuln && detected) fp++;
        else if (tc->expected_vuln && !detected) fn++;

        if (correct) {
            pass++;
            printf("  \033[32m✓\033[0m %-30s ", tc->name);
            if (tc->expected_vuln) printf("\033[90m[vuln→detected]\033[0m\n");
            else printf("\033[90m[safe→ignored]\033[0m\n");
        } else {
            fail++;
            printf("  \033[91m✗\033[0m %-30s ", tc->name);
            if (tc->expected_vuln) printf("\033[91m[vuln→MISSED]\033[0m\n");
            else printf("\033[91m[safe→FALSE_POS]\033[0m\n");
        }
    }

    clock_t end = clock();
    double elapsed = (double)(end - start) / CLOCKS_PER_SEC * 1000;

    printf("\n\033[36m══════════════════════════════════════════════════════════════\033[0m\n");
    printf("\033[1;97m RESULTS\033[0m\n\n");
    
    printf("  \033[32mTrue Positives:\033[0m  %3d  (vulnerabilities correctly detected)\n", tp);
    printf("  \033[32mTrue Negatives:\033[0m  %3d  (safe pages correctly ignored)\n", tn);
    printf("  \033[91mFalse Positives:\033[0m %3d  (safe pages flagged as vuln)\n", fp);
    printf("  \033[91mFalse Negatives:\033[0m %3d  (vulnerabilities missed)\n", fn);

    printf("\n\033[36m──────────────────────────────────────────────────────────────\033[0m\n");
    
    double accuracy = (double)(tp + tn) / NUM_TESTS * 100;
    double precision = tp > 0 ? (double)tp / (tp + fp) * 100 : 0;
    double recall = tp > 0 ? (double)tp / (tp + fn) * 100 : 0;
    double f1 = (precision + recall) > 0 ? 2 * precision * recall / (precision + recall) : 0;
    double fpr = tn + fp > 0 ? (double)fp / (tn + fp) * 100 : 0;
    double fnr = tp + fn > 0 ? (double)fn / (tp + fn) * 100 : 0;

    printf("\n  \033[97mAccuracy:\033[0m       %6.2f%%\n", accuracy);
    printf("  \033[97mPrecision:\033[0m      %6.2f%%\n", precision);
    printf("  \033[97mRecall:\033[0m         %6.2f%%\n", recall);
    printf("  \033[97mF1 Score:\033[0m       %6.2f%%\n", f1);
    printf("  \033[97mFP Rate:\033[0m        %6.2f%%\n", fpr);
    printf("  \033[97mFN Rate:\033[0m        %6.2f%%\n", fnr);

    printf("\n  \033[90mTotal tests:\033[0m    %zu\n", NUM_TESTS);
    printf("  \033[90mTime elapsed:\033[0m   %.2f ms\n", elapsed);

    printf("\n\033[36m══════════════════════════════════════════════════════════════\033[0m\n");
    
    if (fail == 0) {
        printf("\n  \033[1;32m★ ALL TESTS PASSED ★\033[0m\n\n");
    } else {
        printf("\n  \033[1;91m%d/%zu tests failed\033[0m\n\n", fail, NUM_TESTS);
    }

    return fail > 0 ? 1 : 0;
}
