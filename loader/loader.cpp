#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <getopt.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <net/if.h>

#include "common/common.h"
#include "common/netlink_utils.h"
#include "common/bpf_helpers.h"
#include "common/config.h"

static const struct option options[] = {
	{ "help", no_argument, NULL, 'h' },
	{ "interface", required_argument, NULL, 'i' },
	{ "config", required_argument, NULL, 'c' },
	{ "unload", no_argument, NULL, 'u' },
	{ "refresh", no_argument, NULL, 'r' },
	{ 0, 0, NULL, 0 }
};

static void print_usage(char *argv[])
{
	int i;
	printf("Usage:\n");
	printf("%s\n", argv[0]);
	for (i = 0; options[i].name != 0; i++) {
		printf(" --%-12s", options[i].name);
		if (options[i].flag != NULL)
			printf(" flag (internal value:%d)", *options[i].flag);
		else
			printf(" short-option: -%c", options[i].val);
		printf("\n");
	}
	printf("Example:\n");
	printf("To load program:\n%s -i eth0\n", argv[0]);
	printf("To unload program:\n%s -i eth0 -u\n", argv[0]);
	printf("\n");
}

int main(int argc, char **argv)
{
	__u16 ifindex;
    char do_unload = 0;
    char do_refresh = 0;
    int opt;
    char dev[IF_NAMESIZE] = "";
    char config[PATH_MAX] = "";

    if(argc < 2) {
        print_usage(argv);
        return -EINVAL;
    }

    while ((opt = getopt_long(argc, argv, "hrui:c:", options, NULL)) != -1) {
        switch (opt) {
        case 'i':
            strncpy(dev, optarg, IF_NAMESIZE);
            dev[IF_NAMESIZE - 1] = '\0';
            ifindex = if_nametoindex(dev);
            if (ifindex <= 0) {
                printf("Couldn't find ifname:%s \n", dev);
                return -ENODEV;
            }
            break;
        case 'u':
            do_unload = 1;
            break;
        case 'r':
            do_refresh = 1;
            break;
        case 'c':
            strncpy(config, optarg, PATH_MAX);
            config[PATH_MAX - 1] = '\0';
            if(access(config, F_OK)) {
                printf("Couldn't found file:%s \n", config);
                return -ENOENT;
            }
            break;
        case 'h':
            print_usage(argv);
            exit(0);
        default:
            fprintf(stderr, "Unknown option %s\n", argv[optind]);
            return -EINVAL;
        }
    }

    int err = 0;
    int filter_id = 0;
    int cmap_fd = 0;

    int key, value;

    init_netlink();

    if (do_unload) {
        err = remove_netlink_filters(ifindex);
        goto cleanup;
    }

    filter_id = get_filter_id(ifindex);
    if(filter_id > 0 && !do_refresh) {
        err = remove_netlink_filters(ifindex);
        if(err) goto cleanup;
    } else if(filter_id < 0) {
        err = -filter_id;
        goto cleanup;
    }

    int prog_fd[PROG_SIZE];
    if(!do_refresh) {
        load_bpf_program(prog_fd, sizeof(prog_fd)/sizeof(int));
    } else {
        prog_fd[0] = bpf_prog_get_fd_by_id(filter_id);
    }
    if(prog_fd[0] <= 0) {
        err = -prog_fd[0];
        goto cleanup;
    }

    cmap_fd = get_map_fd(prog_fd[0], BPF_CFG_MAP_NAME);

    if(cmap_fd <= 0) {
        printf("config bpf map not found\n");
        err = -cmap_fd;
        goto cleanup;
    }

    err = configure_bpf(cmap_fd, config, false);
    if(err) {
        fprintf(stderr, "ERR: configure BPF object failed by file(%s) (%d): %s\n",
                config, err, strerror(err));
        goto cleanup;
    }


    if(!do_refresh) {
        err = add_netlink_filter(ifindex, prog_fd[3], (char*)bpfipv6rdr_str, sizeof(bpfipv6rdr_str));
        if (err) {
            fprintf(stderr, "ERR: sdp link attach failed(%d) prog %s: %s\n",
                    err, bpfipv4_str, strerror(err));
            goto cleanup;
        }
        err = add_netlink_filter(ifindex, prog_fd[2], (char*)bpfipv4rdr_str, sizeof(bpfipv4rdr_str));
        if (err) {
            fprintf(stderr, "ERR: sdp link attach failed(%d) prog %s: %s\n",
                    err, bpfipv4rdr_str, strerror(err));
            goto cleanup;
        }
        err = add_netlink_filter(ifindex, prog_fd[1], (char*)bpfipv6_str, sizeof(bpfipv6_str));
        if (err) {
            fprintf(stderr, "ERR: sdp link attach failed(%d) prog %s: %s\n",
                    err, bpfipv6_str, strerror(err));
            goto cleanup;
        }
        err = add_netlink_filter(ifindex, prog_fd[0], (char*)bpfipv4_str, sizeof(bpfipv4_str));
        if (err) {
            fprintf(stderr, "ERR: sdp link attach failed(%d) prog %s: %s\n",
                    err, bpfipv4_str, strerror(err));
            goto cleanup;
        }
    }

    printf("Success: Loading xdp program\n");
cleanup:
    close_netlink();
    return -err;
}
