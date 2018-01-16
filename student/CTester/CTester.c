#define _GNU_SOURCE
#include <dlfcn.h>
#include <malloc.h>

#include <stdlib.h>
#include <stdio.h>
#include <setjmp.h>
#include <signal.h>
#include <errno.h>
#include <sys/time.h>

#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>
#include <CUnit/Automated.h>

#include <libintl.h>
#include <locale.h>
#define _(STRING) gettext(STRING)

#include "wrap.h"

extern bool wrap_monitoring;
extern struct wrap_stats_t stats;
extern struct wrap_monitor_t monitored;
extern struct wrap_fail_t failures;
extern struct wrap_log_t logs;

sigjmp_buf segv_jmp;
struct itimerval it_val;

CU_pSuite pSuite = NULL;

struct __test_metadata {
    bool info_prio;
    char info_msg[140];
    char problem[140];
    char descr[250];
    unsigned int weight;
} test_metadata;

void set_test_metadata(char *problem, char *descr, unsigned int weight)
{
    test_metadata.weight = weight;
    strncpy(test_metadata.problem, problem, sizeof(test_metadata.problem));
    strncpy(test_metadata.descr, descr, sizeof(test_metadata.descr));
}

void info(char *msg)
{
    if (!test_metadata.info_prio)
        strncpy(test_metadata.info_msg, msg, sizeof(test_metadata.info_msg));
}


void segv_handler(int sig, siginfo_t *unused, void *unused2)
{
    info(_("Your code produced a segfault."));
    test_metadata.info_prio = 1;
    siglongjmp(segv_jmp, 1);
}

void alarm_handler(int sig, siginfo_t *unused, void *unused2)
{
    info(_("Your code exceeded the maximal allowed execution time."));
    test_metadata.info_prio = 1;
    siglongjmp(segv_jmp, 1);
}


int sandbox_begin()
{
    wrap_monitoring = true;

    // Start timer
    it_val.it_value.tv_sec = 2;
    it_val.it_value.tv_usec = 0;
    it_val.it_interval.tv_sec = 0;
    it_val.it_interval.tv_usec = 0;
    setitimer(ITIMER_REAL, &it_val, NULL);

    // TODO start monitoring / toggle
    return (sigsetjmp(segv_jmp,1) == 0);
}

void sandbox_fail()
{
    CU_FAIL("Segmentation Fault or Timeout");
}

void sandbox_end()
{
    wrap_monitoring = false;

    it_val.it_value.tv_sec = 0;
    it_val.it_value.tv_usec = 0;
    it_val.it_interval.tv_sec = 0;
    it_val.it_interval.tv_usec = 0;
    setitimer(ITIMER_REAL, &it_val, NULL);
}


int init_suite1(void)
{
    return 0;
}

int clean_suite1(void)
{
    return 0;
}

void start_test()
{
    bzero(&test_metadata,sizeof(test_metadata));
    bzero(&stats,sizeof(stats));
    bzero(&failures,sizeof(failures));
    bzero(&monitored,sizeof(monitored));
    bzero(&logs,sizeof(logs));
}

void end_test()
{
}


int __real_exit(int status);
int __wrap_exit(int status){
    return status;
}

int run_tests(void *tests[], int nb_tests) {
    setlocale (LC_ALL, "");
    bindtextdomain("tests", getenv("PWD"));
    bind_textdomain_codeset("messages", "UTF-8");
    textdomain("tests");

    /*Ignore double free*/
    mallopt(M_CHECK_ACTION, 0);

    /* make sure that we catch segmentation faults */
    struct sigaction sa;

    memset(&sa, 0, sizeof(sigaction));
    sigemptyset(&sa.sa_mask);
    static char stack[SIGSTKSZ];
    stack_t ss = {
        .ss_size = SIGSTKSZ,
        .ss_sp = stack,
    };

    sa.sa_flags     = SA_NODEFER|SA_ONSTACK|SA_RESTART;
    sa.sa_sigaction = segv_handler;
    sigaltstack(&ss, 0);
    sigfillset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, NULL);
    sa.sa_sigaction = alarm_handler;
    sigaction(SIGALRM, &sa, NULL);

    /* Output file containing succeeded / failed tests */
    FILE* f_out = fopen("results.txt", "w");
    if (!f_out)
        return -ENOENT;


    /* initialize the CUnit test registry */
    if (CUE_SUCCESS != CU_initialize_registry())
        return CU_get_error();

    //CU_basic_set_mode(CU_BRM_SILENT);
    //CU_basic_set_mode(CU_BRM_VERBOSE);

    /* add a suite to the registry */
    pSuite = CU_add_suite("Suite_1", init_suite1, clean_suite1);
    if (NULL == pSuite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    for (int i=0; i < nb_tests; i++) {
        Dl_info  DlInfo;
        if (dladdr(tests[i], &DlInfo) == 0)
            return -EFAULT;

        CU_pTest pTest;
        if ((pTest = CU_add_test(pSuite, DlInfo.dli_sname, tests[i])) == NULL) {
                CU_cleanup_registry();
                return CU_get_error();
        }

        printf("\n==== Results for test %s : ====\n", DlInfo.dli_sname);

        start_test();
        CU_ErrorCode ret = CU_basic_run_test(pSuite,pTest);
        end_test();

        if (ret != CUE_SUCCESS)
            return CU_get_error();
        int nb = CU_get_number_of_tests_failed();
        if (nb > 0)
            ret = fprintf(f_out, "%s|FAIL|%s|%d|%s\n", test_metadata.problem,
                    test_metadata.descr, test_metadata.weight, test_metadata.info_msg);
        else
            ret = fprintf(f_out, "%s|SUCCESS|%s|%d|%s\n", test_metadata.problem,
                    test_metadata.descr, test_metadata.weight, test_metadata.info_msg);

        if (ret < 0)
            return ret;
    }

    fclose(f_out);

    /* Run all tests using the CUnit Basic interface */
    //CU_basic_run_tests();
    //CU_automated_run_tests();
    CU_cleanup_registry();
    return CU_get_error();
}
