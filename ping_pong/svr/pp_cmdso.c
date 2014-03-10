#include "pp_cmdso.h"

static int pp_cmdso_slot;

static long 
pp_pkg_handler(ngx_tcp_ctx_t *ctx, const u_char *pkg, int pkg_len);


long 
cmdso_load(void *cycle_param, cmd_pkg_handler_add_pt add_h, int slot)
{
    pp_cmdso_slot = slot;
    if (0 != (*add_h)(cycle_param, PP_CMD_CS, PP_CMD_CS, pp_pkg_handler)) {
        return -1;
    }

    return 0;
}


long 
cmdso_unload(void *cycle_param)
{

    return 0;
}


static long 
pp_pkg_handler(ngx_tcp_ctx_t *ctx, const u_char *pkg, int pkg_len)
{
    // ngx_str_t                       pp_str;
    ngx_tcp_cmd_pkghead_t      *pkghead;
    //uint32_t                        pkg_size;

    *((int *) ctx->cmdso_sessioin[pp_cmdso_slot]) += 1;

    pkghead = (ngx_tcp_cmd_pkghead_t *) pkg;
    //pkg_size = pkghead->size;
    //pp_str.data = pkg + CMD_SESSION_PKG_HEAD_LEN;
    //pp_str.len = pkghead->size - CMD_SESSION_PKG_HEAD_LEN;

    ctx->log_error(NGX_TCP_LOG_INFO, ctx->log, 0, 
        "pp_pkg_handler|pkg_size=%d|str=%s\n",
            pkghead->size, pkg + CMD_SESSION_PKG_HEAD_LEN);

    pkghead->cmd = PP_CMD_SC;
    ngx_tcp_cmd_pkghead_hton(pkghead);
    (*(ctx->send_data))(ctx, pkg, pkg_len);

    /* pkg is const so restore the value */
    ngx_tcp_cmd_pkghead_hton(pkghead);

    return 0;
}


long 
cmdso_sess_init(ngx_tcp_ctx_t *ctx)
{
    ctx->cmdso_sessioin[pp_cmdso_slot] = malloc(sizeof(int));
    *((int *) ctx->cmdso_sessioin[pp_cmdso_slot]) = 0;

    return 0;
}


long 
cmdso_sess_finit(ngx_tcp_ctx_t *ctx)
{
    free(ctx->cmdso_sessioin[pp_cmdso_slot]);

    return 0;
}
