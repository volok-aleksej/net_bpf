#ifndef BPF_LOGGER_H
#define BPF_LOGGER_H

#define STR_SIZE(str) sizeof(str)

char REDIRECT_UDP_LOG[] = "try udp redirect";
char REDIRECT_TCP_LOG[] = "try tcp redirect";
char REDIRECT_FRAGMENT_LOG[] = "try redirect fragment";
char REDIRECT_MESSAGE_LOG[] = "send next buffer";
char IP6_TMP_LOG[] = "fragment ip6";

static __always_inline void log_str(struct ebpf_context* ctx, struct __sk_buff *skb, const char* data, unsigned int len)
{
    struct LogData* log = (struct LogData*)ctx->log_buf;
    log->type = LOG_STRING;
    bpf_probe_read_kernel_str(log->data, len, data);
    bpf_perf_event_output(skb, &log_ring_map, BPF_F_INDEX_MASK, ctx->log_buf, sizeof(struct LogData) + len);
}

static __always_inline void log_binari(struct ebpf_context* ctx, struct __sk_buff *skb, const char* data, unsigned int len)
{
    struct LogData* log = (struct LogData*)ctx->log_buf;
    log->type = LOG_BINARY;
    if(len > LOG_BUFFER_SIZE - sizeof(struct LogData)) len = LOG_BUFFER_SIZE - sizeof(struct LogData);
    bpf_probe_read_kernel(log->data, len, data);
    bpf_perf_event_output(skb, &log_ring_map, BPF_F_INDEX_MASK, ctx->log_buf, sizeof(struct LogData) + len);
}

#endif/*BPF_LOGGER_H*/
