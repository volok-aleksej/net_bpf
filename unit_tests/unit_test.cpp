#include <getopt.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "unit_test.h"
#include "gtest/gtest.h"
#include "common/common.h"
#include "common/netlink_utils.h"
#include "common/bpf_helpers.h"
#include "common/config.h"

#define GRE_HEADER_SIZE 4
#define GRE_IPV4_MTU MTU-sizeof(struct iphdr)-GRE_HEADER_SIZE

static const struct option options[] = {
	{ "config", required_argument, NULL, 'c' },
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
	printf("Run tests:\n%s -i eth0 -c ./net.bpf.cfg\n", argv[0]);
	printf("\n");
}

int ipv4_fd = 0;
int ipv6_fd = 0;
int ipv4_rdr_fd = 0;
int ipv6_rdr_fd = 0;

int main(int argc, char **argv)
{    
    int opt;
    char config[PATH_MAX] = "";

    if(argc < 2) {
        print_usage(argv);
        return -EINVAL;
    }

    while ((opt = getopt_long(argc, argv, "hc:", options, NULL)) != -1) {
        switch (opt) {
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
        }
    }

    int err = 0;
    int cmap_fd = 0;

    init_netlink();

    int prog_fd[PROG_SIZE] = {0};
    int prog_size = load_bpf_program(prog_fd, sizeof(prog_fd));
    if(prog_size != PROG_SIZE) {
        printf("incorrect bpf file: prog_size(%u) != %u\n", prog_size, PROG_SIZE);
        goto cleanup;
    }

    for(int i = 0; i < prog_size; i++) {
        struct bpf_prog_info prog_info;
        __u32 prog_len = 0;
        int err = 0;

        memset(&prog_info, 0, sizeof(prog_info));
        prog_len = sizeof(prog_info);
        err = bpf_obj_get_info_by_fd(prog_fd[i], &prog_info, &prog_len);
        if(err) {
            printf("don't get info from bpf program: index %d prog_fd %d\n", i, prog_fd[i]);
            goto cleanup;
        }
        if(strlen(prog_info.name) == sizeof(bpfipv4_str) - 1 &&
           !strncmp(prog_info.name, bpfipv4_str, sizeof(bpfipv4_str) - 1)) {
            ipv4_fd = prog_fd[i];
        }
        else if(strlen(prog_info.name) == sizeof(bpfipv6_str) - 1 &&
                !strncmp(prog_info.name, bpfipv6_str, sizeof(bpfipv6_str) - 1)) {
            ipv6_fd = prog_fd[i];
        }
        else if(strlen(prog_info.name) == sizeof(bpfipv4rdr_str) - 1 &&
                !strncmp(prog_info.name, bpfipv4rdr_str, sizeof(bpfipv4rdr_str) - 1)) {
            ipv4_rdr_fd = prog_fd[i];
        }
        else if(strlen(prog_info.name) == sizeof(bpfipv6rdr_str) - 1 &&
                !strncmp(prog_info.name, bpfipv6rdr_str, sizeof(bpfipv6rdr_str) - 1)) {
            ipv6_rdr_fd = prog_fd[i];
        }
    }
    
    cmap_fd = get_map_fd(prog_fd[0], BPF_CFG_MAP_NAME);

    if(cmap_fd <= 0) {
        printf("bpf config map not found\n");
        err = -cmap_fd;
        goto cleanup;
    }

    err = configure_bpf(cmap_fd, config, true);
    if(err) {
        fprintf(stderr, "ERR: configure BPF object failed by file(%s) (%d): %s\n",
                config, err, strerror(err));
        goto cleanup;
    }

    testing::InitGoogleTest(&argc, argv);
    err = RUN_ALL_TESTS();
cleanup:
    close_netlink();
    return -err;
}
