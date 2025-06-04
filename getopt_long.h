#ifndef GETOPT_LONG_H
#define GETOPT_LONG_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * This is a customized version of getopt_long for Windows/cross-platform use.
 * It provides similar functionality to the GNU getopt_long.
 *
 * This header should be accompanied by getopt_long.c
 */

struct option {
    const char *name;
    int has_arg;
    int *flag;
    int val;
};

#define no_argument       0
#define required_argument 1
#define optional_argument 2

extern char *optarg;
extern int optind, opterr, optopt;

int getopt_long(int argc, char *const *argv, const char *optstring,
                const struct option *longopts, int *longindex);

#ifdef __cplusplus
}
#endif

#endif /* GETOPT_LONG_H */
