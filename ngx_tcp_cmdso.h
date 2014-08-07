
#ifndef _NGX_TCP_CMDSO_H_
#define _NGX_TCP_CMDSO_H_

#include <sys/types.h>
#include <stdint.h>
#include <netinet/in.h>

/* */
typedef intptr_t        ngx_tcp_int_t;
typedef uintptr_t       ngx_tcp_uint_t;
typedef intptr_t        ngx_tcp_flag_t;
typedef int             ngx_tcp_err_t;

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

typedef struct ngx_tcp_ctx_s ngx_tcp_ctx_t;

typedef long (*ngx_tcp_send_data_pt)(ngx_tcp_ctx_t *ctx, 
                                     const u_char *data, 
                                     int len);

typedef void (*ngx_tcp_log_error_pt)(ngx_tcp_uint_t level, void *log, 
                                     ngx_tcp_err_t err, 
                                     const char *fmt, ...);

typedef void *(*ngx_tcp_alloc_pt)(void *pool, size_t size);
typedef ngx_tcp_int_t (*ngx_tcp_pfree_pt)(void *pool, void *p);

typedef ngx_tcp_int_t (*ngx_tcp_conf_get_str_pt)(const char *section,
    const char *k, char **v);

struct ngx_tcp_log_s {
    void                    *log;
    uintptr_t                log_level;
    ngx_tcp_log_error_pt     log_error;
};
typedef struct ngx_tcp_log_s ngx_tcp_log_t;

struct ngx_tcp_ctx_s {
    /* cmdso_sessioin array. the slot is init in cmdso_load func */
    void                   **cmdso_sessioin;
    void                    *ngx_tcp_session;
    ngx_tcp_send_data_pt     send_data;

    ngx_tcp_conf_get_str_pt  conf_get_str;
    uintptr_t               *current_msec;
    
    ngx_tcp_log_t            tcp_log_t;

    void                    *pool;
    ngx_tcp_alloc_pt         palloc;
    ngx_tcp_alloc_pt         pcalloc;
    ngx_tcp_pfree_pt         pfree;
};

struct ngx_tcp_cycle_ctx_s {
	   ngx_tcp_conf_get_str_pt   conf_get_str;
	   ngx_tcp_log_t             tcp_log_t;
};

typedef struct ngx_tcp_cycle_ctx_s ngx_tcp_cycle_ctx_t;

typedef long (*cmd_pkg_handler_pt)(ngx_tcp_ctx_t *ctx, 
                                   const u_char *pkg, 
                                   int pkg_len);
/* pkg = head + body. Filter result must be the same as this format. */
typedef long (*cmd_pkg_filter_pt)(ngx_tcp_ctx_t *ctx,
                                  u_char **pkg,
                                  int pkg_len);

typedef long
(*cmd_pkg_handler_add_pt)(void *cycle_param, 
                          uint32_t cmd_min, uint32_t cmd_max,
                          cmd_pkg_handler_pt h);
typedef long
(*cmd_pkg_filter_add_pt)(void *cycle_param, cmd_pkg_filter_pt h);


#define CMDSO_LOAD          "cmdso_load"
#define CMDSO_UNLOAD        "cmdso_unload"
#define CMDSO_SESS_INIT     "cmdso_sess_init"
#define CMDSO_SESS_FINIT    "cmdso_sess_finit"

typedef long 
(*cmdso_load_pt)(void *cycle_param, cmd_pkg_handler_add_pt add_h, cmd_pkg_filter_add_pt add_filter_h, 
                 int slot, ngx_tcp_cycle_ctx_t *cycle_ctx);

typedef long (*cmdso_unload_pt)(void *cycle_param);
typedef long (*cmdso_sess_init_pt)(ngx_tcp_ctx_t *ctx);
typedef long (*cmdso_sess_finit_pt)(ngx_tcp_ctx_t *ctx);

typedef struct {
    void                *handle;
    cmdso_load_pt        cmdso_load;
    cmdso_unload_pt      cmdso_unload;
    cmdso_sess_init_pt   cmdso_sess_init;
    cmdso_sess_finit_pt  cmdso_sess_finit;
} ngx_tcp_cmdso_t;


#pragma pack(push, 1)
#if 1
typedef struct {
    /* size == pkg_head + pkg_body */
    uint32_t size;
    uint32_t cmd;

    /* padding */
    uint32_t spare0;
    uint32_t spare1;
    uint32_t spare2;
    uint32_t spare3;
    uint32_t spare4;
    uint32_t spare5;
} ngx_tcp_cmd_pkghead_t;
#endif
typedef struct {
    pid_t      dest_pid;
    int32_t    dest_fd;
    uint32_t   data_size;
    u_char     data[0];
} ngx_tcp_cmd_pkgtran_t;
#define CMD_SESSION_PKG_HEAD_LEN sizeof(ngx_tcp_cmd_pkghead_t)
#pragma pack(pop)


static inline void 
ngx_tcp_cmd_pkghead_hton(ngx_tcp_cmd_pkghead_t *pkghead)
{
    pkghead->size      = htonl(pkghead->size);
    pkghead->cmd       = htonl(pkghead->cmd);
}


static inline void 
ngx_tcp_cmd_pkghead_ntoh(ngx_tcp_cmd_pkghead_t *pkghead)
{
    pkghead->size      = ntohl(pkghead->size);
    pkghead->cmd       = ntohl(pkghead->cmd);
}


#define NGX_TCP_CMD_KEEPALIVE 1
#define NGX_TCP_CMD_TRAN 2
#define NGX_TCP_CMD_MAX_PKG_SIZE (1024 * 1024 * 4)

# ifdef __cplusplus
extern "C" {
# endif

  /* The dynamic shared object must implement this function for loading. */
  long cmdso_load(void *cycle_param, cmd_pkg_handler_add_pt add_h, cmd_pkg_filter_add_pt add_filter_h,
      int slot, ngx_tcp_cycle_ctx_t *cycle_ctx);
  long cmdso_unload(void *cycle_param);
  long cmdso_sess_init(ngx_tcp_ctx_t *ctx);
  long cmdso_sess_finit(ngx_tcp_ctx_t *ctx);

# ifdef __cplusplus
}
# endif

#endif

