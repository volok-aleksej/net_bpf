#include <errno.h>
#include <stdlib.h>
#include <signal.h>

#include <linux/perf_event.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <net/if.h>
#include "common/netlink_utils.h"
#include "common/bpf_helpers.h"
#include "common/common.h"

#define XDP_OBJ "net.bpf"

struct perf_event
{
    struct perf_event_header header;
    __u32 size;
    void* data;
};

static void print_usage(char *argv[])
{
	int i;
	printf("Usage:\n");
	printf("%s <interface name>\n", argv[0]);
	printf("\n");
}

static void print_bpf_output(void *ctx, int cpu, void *data, __u32 size)
{
    struct LogData *log = (struct LogData *)data;
    if(log->type == LogData::LOG_STRING)
        printf("string:%s\n", (char*)log->data);
    else if(log->type == LogData::LOG_BINARY) {
        printf("binari:");
        size -= sizeof(__u32) + sizeof(struct LogData); 
        for(int i = 0; i < size; i++) {
                if(!(i%16)) printf("\n");
            printf("%.2x ", *((char*)log->data + i)&0xff);
        }
        printf("\n");
    }
}

static volatile bool finished = false;

void signal_handler(int signum) {
   printf("Interrupt signal (%d) received.\n", signum);
   // cleanup and close up stuff here  
   // terminate program
   finished = true;
}

int main(int argc, char **argv)
{
    if(argc < 2) {
        print_usage(argv);
        return -EINVAL;
    }
    
    signal(SIGTERM, signal_handler);
    signal(SIGABRT, signal_handler);
    signal(SIGINT, signal_handler);

    init_netlink();
    char dev[IF_NAMESIZE] = "";
    strncpy(dev, argv[1], IF_NAMESIZE);
    dev[IF_NAMESIZE - 1] = '\0';
    int ifindex = if_nametoindex(dev);
    if (ifindex <= 0) {
        printf("Couldn't find ifname:%s \n", dev);
        close_netlink();
        return -ENODEV;
    }
    struct perf_buffer* pb;
 	struct perf_buffer_opts opts = {0};
    
    int filter_id = get_filter_id(ifindex);
    if(filter_id < 0) {
        close_netlink();
        return filter_id;
    } else if(!filter_id) {
        printf("filter clsact not found\n");
        close_netlink();
        return -ENODEV;
    }

    opts.sample_cb = &print_bpf_output;
    int prog_fd = bpf_prog_get_fd_by_id(filter_id);
    int map_fd = get_map_fd(prog_fd, BPF_MON_MAP_NAME);
	pb = perf_buffer__new(map_fd, 16, &opts);
	int err = libbpf_get_error(pb);
	if (err) {
		printf("failed to setup perf_buffer: %d\n", err);
        close_netlink();
		return -err;
	}

	while ((err = perf_buffer__poll(pb, 1000)) >= 0 && !finished) {}

	perf_buffer__free(pb);
    close_netlink();
    return 0;
}
