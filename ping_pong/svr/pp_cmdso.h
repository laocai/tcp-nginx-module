
#ifndef _PP_CMDSO_H_INCLUDED_
#define _PP_CMDSO_H_INCLUDED_

#include "../../ngx_tcp_cmdso.h"

#define PP_CMD_CS 100
#define PP_CMD_SC 101

long cmdso_load(void *cycle_param, cmd_pkg_handler_add_pt add_h, int slot);
long cmdso_unload(void *cycle_param);
long cmdso_sess_init(ngx_tcp_ctx_t *ctx);
long cmdso_sess_finit(ngx_tcp_ctx_t *ctx);

#endif
