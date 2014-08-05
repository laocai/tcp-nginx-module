#include "pp_cmdso.h"

static int pp_cmdso_slot;

static long 
pp_pkg_handler(ngx_tcp_ctx_t *ctx, const u_char *pkg, int pkg_len);


long 
cmdso_load(void *cycle_param, cmd_pkg_handler_add_pt add_h, cmd_pkg_filter_add_pt add_filter_h, 
    int slot, ngx_tcp_cycle_ctx_t *cycle_ctx)
{
	ngx_tcp_log_error(&cycle_ctx->tcp_log_t,NGX_TCP_LOG_INFO, 0, 
			"cmdso_load|slot=%d", slot);
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
    ngx_tcp_cmd_pkghead_t      *pkghead;
    char                       *ini_section = "pp";
    char                       *pp_key = "pp_key";
    char                       *pp_val;

    *((int *) ctx->cmdso_sessioin[pp_cmdso_slot]) += 1;

    pkghead = (ngx_tcp_cmd_pkghead_t *) pkg;

    if (ctx->conf_get_str(ini_section, pp_key, &pp_val) != 0) {
        pp_val = "no ini pp_key val";
    }

    ngx_tcp_log_error(&ctx->tcp_log_t, NGX_TCP_LOG_INFO, 0, 
        "pp_pkg_handler|pkg_size=%d|str=%s|pp_val=%s\n",
            pkghead->size, pkg + CMD_SESSION_PKG_HEAD_LEN, pp_val);

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
    ctx->cmdso_sessioin[pp_cmdso_slot] = (*(ctx->palloc))(ctx->pool, sizeof(int));
    *((int *) ctx->cmdso_sessioin[pp_cmdso_slot]) = 0;

    return 0;
}


long 
cmdso_sess_finit(ngx_tcp_ctx_t *ctx)
{
    (*(ctx->pfree))(ctx->pool, ctx->cmdso_sessioin[pp_cmdso_slot]);

    return 0;
}
