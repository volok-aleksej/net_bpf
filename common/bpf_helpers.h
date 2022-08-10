#ifndef BPF_HELPERS_H
#define BPF_HELPERS_H

int load_bpf_program(int* fds, int size);
int get_map_fd(int prog_fd, const char* map_name);

#endif/*BPF_HELPERS_H*/
