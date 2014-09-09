
#ifndef _NGX_TCP_CMDSO_H_
#define _NGX_TCP_CMDSO_H_

#include <ngx_tcp_export.h>

///* g_cycle_ctx is declared here must be defined in dynamic shared object,
// * must be initialized in cmdso_load from the param cycle_ctx.
// */
//extern ngx_tcp_cycle_ctx_t *g_cycle_ctx;

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

/**
 * to_call_first indicate the filter function to be call first in all filter
 * If these are more than two first call filters,only one will be valid, others
 * were lost.
 */
typedef long
(*cmd_pkg_filter_add_pt)(void *cycle_param, cmd_pkg_filter_pt h, int to_call_first);


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

