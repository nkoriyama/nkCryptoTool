#include "getopt_long.h"
#include <stdio.h>
#include <string.h>

char *optarg = NULL;
int optind = 1;
int opterr = 1;
int optopt = '?';

int getopt_long(int argc, char *const *argv, const char *optstring,
                const struct option *longopts, int *longindex) {
    static int last_optind = 1;
    char *p;

    if (optind != last_optind) {
        last_optind = optind;
        optarg = NULL;
    }

    if (optind >= argc)
        return -1;

    char *current_arg = argv[optind];

    // Handle -- (end of options)
    if (strcmp(current_arg, "--") == 0) {
        optind++;
        return -1;
    }

    // Handle long options (--option or --option=value)
    if (current_arg[0] == '-' && current_arg[1] == '-') {
        char *option_name = current_arg + 2;
        char *equal_sign = strchr(option_name, '=');
        int name_len = (equal_sign ? (int)(equal_sign - option_name) : (int)strlen(option_name));

        for (int i = 0; longopts[i].name != NULL; ++i) {
            if (strncmp(option_name, longopts[i].name, name_len) == 0 &&
                (longopts[i].name[name_len] == '\0' || longopts[i].name[name_len] == '=')) { // Check for exact match or match up to '='

                if (longindex != NULL) {
                    *longindex = i;
                }

                optind++;
                optopt = longopts[i].val; // Set optopt to the value for the long option

                if (equal_sign) { // Argument provided via '='
                    optarg = equal_sign + 1;
                    if (longopts[i].has_arg == no_argument) {
                        if (opterr) fprintf(stderr, "Error: Option --%s does not allow an argument.\n", longopts[i].name);
                        return '?';
                    }
                } else if (longopts[i].has_arg == required_argument) {
                    if (optind < argc) {
                        optarg = argv[optind];
                        optind++;
                    } else {
                        if (opterr) fprintf(stderr, "Error: Option --%s requires an argument.\n", longopts[i].name);
                        return '?'; // Missing required argument
                    }
                } else if (longopts[i].has_arg == optional_argument) {
                    // No argument provided, optarg remains NULL
                }

                if (longopts[i].flag != NULL) {
                    *(longopts[i].flag) = longopts[i].val;
                    return 0; // Return 0 if flag is set
                } else {
                    return longopts[i].val;
                }
            }
        }
        if (opterr) fprintf(stderr, "Error: Unrecognized option --%s\n", option_name);
        optopt = 0; // Set optopt to 0 for unrecognized long options
        optind++;
        return '?'; // Unrecognized long option
    }

    // Handle short options (-o or -ovalue or -abc)
    if (current_arg[0] == '-') {
        p = current_arg + 1;
        if (*p == '\0') { // Just "-"
            optind++;
            return -1;
        }

        char c = *p++;
        const char *optdef = strchr(optstring, c);

        if (optdef == NULL) { // Unrecognized short option
            if (opterr) fprintf(stderr, "Error: Unrecognized option -%c\n", c);
            optopt = c;
            optind++;
            return '?';
        }

        if (*(optdef + 1) == ':') { // Option requires an argument
            if (*p != '\0') { // Argument follows immediately
                optarg = p;
                optind++;
            } else if (optind + 1 < argc) { // Argument is next argv element
                optarg = argv[optind + 1];
                optind += 2;
            } else {
                if (opterr) fprintf(stderr, "Error: Option -%c requires an argument.\n", c);
                optopt = c;
                return '?'; // Missing required argument
            }
        } else if (*(optdef + 1) == ';') { // Option has an optional argument
            if (*p != '\0') { // Argument follows immediately
                optarg = p;
            } else {
                optarg = NULL; // No argument provided
            }
            optind++;
        } else { // Option takes no argument
            optarg = NULL;
            optind++;
        }
        return c;
    }

    // Not an option, it's a non-option argument
    return -1;
}
