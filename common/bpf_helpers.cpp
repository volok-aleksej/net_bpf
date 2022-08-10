#include <errno.h>
#include <fcntl.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "common.h"
#include "config.h"
#include "bpf_helpers.h"

static __u64 ptr_to_u64(void *ptr)
{
	return (__u64) (unsigned long) ptr;
}

int load_bpf_program(int* fds, int size)
{
    int err;
    struct bpf_object *obj = NULL;
    char filename[256] = XDP_OBJ;
    obj = bpf_object__open(filename);
    err = ::libbpf_get_error(obj);
    if (err) {
        fprintf(stderr, "ERR: loading BPF-OBJ file(%s) (%d): %s\n",
            filename, err, strerror(err));
        return -err;
    }
    int tmp;
    bpf_prog_load(filename, BPF_PROG_TYPE_SCHED_CLS, &obj, &tmp);
    err = ::libbpf_get_error(obj);
    if (err) {
        printf("ERR: loading file: %s\n", filename);
        bpf_object__close(obj);
        return -err;
    };
    bool abort = false;
    int prog_size = 0;
    struct bpf_program* prog = 0;
    bpf_object__for_each_program(prog, obj){
        if(prog_size == size) abort = true;
        int prog_fd = bpf_program__fd(prog);
        if(!prog_fd) abort = true;
        if(!abort) {
            prog_fd = fcntl(prog_fd, F_DUPFD_CLOEXEC, 1);
            fds[prog_size] = prog_fd;
        }
        prog_size++;
    }
    bpf_object__unload(obj);
    bpf_object__close(obj);
    return prog_size;
}
int get_map_fd(int prog_fd, const char* map_name)
{
    int nr_maps = 0;
    struct bpf_prog_info prog_info;
    __u32 prog_len = 0;
    __u32* map_ids = 0;
    int err = 0;

    memset(&prog_info, 0, sizeof(prog_info));
    prog_len = sizeof(prog_info);
    err = bpf_obj_get_info_by_fd(prog_fd, &prog_info, &prog_len);
    if(err) {
        printf("don't get info from bpf program\n");
        return 0;
    } else if(!prog_info.nr_map_ids) {
        printf("bpf program doesn't have maps\n");
        return 0;
    }

    nr_maps = prog_info.nr_map_ids;
    memset(&prog_info, 0, sizeof(prog_info));
    map_ids = new __u32[nr_maps];
    prog_info.nr_map_ids = nr_maps;
    prog_info.map_ids = ptr_to_u64(map_ids);
    prog_len = sizeof(prog_info);
    err = bpf_obj_get_info_by_fd(prog_fd, &prog_info, &prog_len);
    if(err) {
        printf("don't get info from bpf program\n");
        goto free_maps;
    }

    for (int i = 0; i < prog_info.nr_map_ids; i++) {
        int map_fd = bpf_map_get_fd_by_id(map_ids[i]);
        struct bpf_map_info map_info = {0};
        __u32 map_len = sizeof(map_info);
        err = bpf_obj_get_info_by_fd(map_fd, &map_info, &map_len);
        if(err) {
            printf("don't get info from bpf map\n");
            goto free_maps;
        }
        if(strcmp(map_info.name, map_name) == 0) {
            err = map_fd;
            break;
        }
    }
free_maps:
    delete[] map_ids;
    return err;
}
