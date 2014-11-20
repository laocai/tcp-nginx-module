#ifndef _NGX_TCP_EXPORT_FUNC_H_
#define _NGX_TCP_EXPORT_FUNC_H_

#include <ngx_tcp_export_type.h>

#define NGX_TCP_LOG_STDERR            0
#define NGX_TCP_LOG_EMERG             1
#define NGX_TCP_LOG_ALERT             2
#define NGX_TCP_LOG_CRIT              3
#define NGX_TCP_LOG_ERR               4
#define NGX_TCP_LOG_WARN              5
#define NGX_TCP_LOG_NOTICE            6
#define NGX_TCP_LOG_INFO              7
#define NGX_TCP_LOG_DEBUG             8

#define ngx_tcp_log_error(tcp_log_ptr, level, ...) \
    if ((tcp_log_ptr)->log_level >= level) (tcp_log_ptr)->log_error(level, (tcp_log_ptr)->log, __VA_ARGS__)

typedef struct ngx_tcp_cycle_ctx_s ngx_tcp_cycle_ctx_t;
typedef struct ngx_tcp_ctx_s ngx_tcp_ctx_t;

typedef ngx_tcp_ctx_t *(*ngx_tcp_get_ctx_pt)(ngx_tcp_cycle_ctx_t *cycle_ctx, int fd);

typedef long (*ngx_tcp_send_data_pt)(ngx_tcp_ctx_t *ctx, 
                                     const u_char *data, 
                                     int len);
typedef long (*ngx_tcp_send_cmddata_pt)(ngx_tcp_ctx_t *ctx, 
                                     u_char *data, 
                                     int len);


typedef void (*ngx_tcp_log_error_pt)(ngx_tcp_uint_t level, void *log, 
                                     ngx_tcp_err_t err, 
                                     const char *fmt, ...);

/* the result 'v' is no need to free */
typedef ngx_tcp_int_t (*ngx_tcp_conf_get_str_pt)(const char *section,
    const char *k, char **v);

struct ngx_tcp_log_s {
    void                    *log;
    uintptr_t                log_level;
    ngx_tcp_log_error_pt     log_error;
};
typedef struct ngx_tcp_log_s ngx_tcp_log_t;

typedef struct
{
    ngx_tcp_conf_get_str_pt conf_get_str;

    ngx_tcp_log_t log;

    ngx_tcp_send_data_pt send_data;
    ngx_tcp_send_cmddata_pt send_cmd_data;

    ngx_tcp_get_ctx_pt get_ctx;

} ngx_tcp_export_func_t;

#endif

