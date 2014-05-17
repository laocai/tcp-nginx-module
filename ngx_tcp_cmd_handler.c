
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_tcp.h>
#include <ngx_tcp_cmd_module.h>
#include <ngx_map.h>


static ngx_buf_t *ngx_buf_compact(ngx_buf_t *buffer);

static void
ngx_tcp_cmd_handle(ngx_event_t *rev);

ngx_tcp_session_t *
ngx_tcp_cmd_create_session(ngx_connection_t *c)
{
    ngx_tcp_session_t          *s;
    ngx_chain_writer_ctx_t     *filter_ctx;

    s = ngx_pcalloc(c->pool, sizeof(ngx_tcp_cmd_session_t));
    if (s == NULL) {
        goto failed;
    }
    s->tcp_ctx.cmdso_sessioin = ngx_pcalloc(c->pool, 
                                    sizeof(void *) * cmdso_mgr->cmdsos.nelts);
    if (s->tcp_ctx.cmdso_sessioin == NULL) {
        goto failed;
    }
    s->tcp_ctx.conf_get_str = (ngx_tcp_conf_get_str_pt)ngx_tcp_cmd_conf_get_str;
    s->tcp_ctx.tcp_log_t.log = c->log;
    s->tcp_ctx.tcp_log_t.log_level = c->log->log_level;
    s->tcp_ctx.tcp_log_t.log_error = (ngx_tcp_log_error_pt)ngx_log_error_core;
    s->tcp_ctx.send_data = ngx_tcp_send_data;
    s->tcp_ctx.pool = c->pool;
    s->tcp_ctx.palloc = (ngx_tcp_alloc_pt)ngx_palloc;
    s->tcp_ctx.pcalloc = (ngx_tcp_alloc_pt)ngx_pcalloc;
    s->tcp_ctx.pfree = (ngx_tcp_pfree_pt)ngx_pfree;

    s->tcp_ctx.ngx_tcp_session = s;
    s->output_ctx = ngx_pcalloc(c->pool, sizeof(ngx_output_chain_ctx_t));
    if (s->output_ctx == NULL) {
        goto failed;
    }
    s->output_ctx->pool = c->pool;
   // s->output_ctx->output_filter = ngx_chain_writer;
    s->output_ctx->output_filter = ngx_tcp_chain_writer;
    filter_ctx = ngx_pcalloc(c->pool, sizeof(ngx_chain_writer_ctx_t));
    if (filter_ctx == NULL) {
        goto failed;
    }
    filter_ctx->connection = c;
    filter_ctx->pool = c->pool;
    filter_ctx->last = &filter_ctx->out;
    s->output_ctx->filter_ctx = filter_ctx;

    return s;

failed:
    return NULL;
}

void
ngx_tcp_cmd_init_session(ngx_tcp_session_t *s, ngx_connection_t *c)
{
    ngx_log_error(NGX_LOG_INFO, c->log, 0, "%s|%d|%s|", __FILE__, __LINE__, __FUNCTION__);
    ngx_tcp_core_main_conf_t   *cmcf;
    ngx_tcp_core_srv_conf_t    *cscf;
    socketfd_info_t            *socketfd_info;
    ngx_uint_t                  i;
    ngx_tcp_cmdso_t            *cmdsos;

    cmcf = ngx_tcp_get_module_main_conf(s, ngx_tcp_core_module);
    cscf = ngx_tcp_get_module_srv_conf(s, ngx_tcp_core_module);

    s->buffer = ngx_create_temp_buf(c->pool, NGX_MAX_ALLOC_FROM_POOL + 1);

    c->read->handler = ngx_tcp_cmd_init_protocol;

    int tcp_nodelay = 1;
    setsockopt(c->fd, IPPROTO_TCP, TCP_NODELAY,
               (const void *) &tcp_nodelay, sizeof(int));

    socketfd_info = cmcf->socketfd_shm->info->socketfd_info + c->fd;
    socketfd_info->listening_unix_info_i = ngx_process_slot;
    socketfd_info->tag = s;    

    ngx_add_timer(c->read, cscf->timeout);
    ngx_log_error(NGX_LOG_INFO, c->log, 0, "%s|%d|%s|%03M", __FILE__, __LINE__, __FUNCTION__, cscf->timeout);
    if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, 
            "%s|%d|%s|ngx_handle_read_event|client=%V|fd=%d\n", 
                __FILE__, __LINE__, __FUNCTION__, &c->addr_text, c->fd);
        ngx_tcp_close_connection(c);
        return;
    }
    
    cmdsos = cmdso_mgr->cmdsos.elts;
    for (i=0; i < cmdso_mgr->cmdsos.nelts; ++i) {
        if (cmdsos[i].cmdso_sess_init(& s->tcp_ctx) != 0) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0, 
                "%s|%d|%s|cmdso_sess_init|client=%V|fd=%d\n", 
                __FILE__, __LINE__, __FUNCTION__, &c->addr_text, c->fd);
            ngx_tcp_close_connection(c);
            return;
        }
    }

    ngx_log_error(NGX_LOG_INFO, c->log, 0, 
        "ngx_tcp_cmd_init_session|client=%V|fd=%d\n", 
            &c->addr_text, c->fd);

    ngx_tcp_send(c->write);
}

void
ngx_tcp_cmd_finit_session(ngx_tcp_session_t *s)
{
    ngx_tcp_core_main_conf_t    *cmcf;
    ngx_connection_t            *c;
    socketfd_info_t             *socketfd_info;
    ngx_uint_t                   i;
    ngx_tcp_cmdso_t             *cmdsos;

    c = s->connection;
    cmdsos = cmdso_mgr->cmdsos.elts;
    for (i=0; i < cmdso_mgr->cmdsos.nelts; ++i) {
        if (cmdsos[i].cmdso_sess_finit(& s->tcp_ctx) != 0) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0, 
                "ngx_tcp_cmd_init_session|cmdso_sess_finit|client=%V|fd=%d\n", 
                &c->addr_text, c->fd);
        }
    }

    cmcf = ngx_tcp_get_module_main_conf(s, ngx_tcp_core_module);
    socketfd_info = cmcf->socketfd_shm->info->socketfd_info + c->fd;
    ngx_memzero(socketfd_info, sizeof(socketfd_info_t));
    ngx_log_error(NGX_LOG_INFO, c->log, 0, 
        "ngx_tcp_cmd_finit_session|client=%V|fd=%d\n", 
            &c->addr_text, c->fd);
}

void
ngx_tcp_cmd_init_protocol(ngx_event_t *rev)
{
    ngx_connection_t    *c;

    c = rev->data;

    c->log->action = "init protocol finished";

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "%s|%d|%s|client timed out",__FILE__, __LINE__, __FUNCTION__);
        c->timedout = 1;
        ngx_tcp_close_connection(c);
        return;
    }

    c->read->handler = ngx_tcp_cmd_handle;
    ngx_tcp_cmd_handle(rev);
}

void
ngx_tcp_cmd_handle(ngx_event_t *rev)
{
    ngx_tcp_core_srv_conf_t         *cscf;
    ngx_int_t                        rc;
    ngx_connection_t                *c;
    ngx_tcp_session_t               *s;
    ssize_t                          n;
    ngx_tcp_cmd_srv_conf_t          *iscf;

    c = rev->data;
    s = (ngx_tcp_session_t *) c->data;
    iscf = ngx_tcp_get_module_srv_conf(s, ngx_tcp_cmd_module);
    cscf = ngx_tcp_get_module_srv_conf(s, ngx_tcp_core_module);

    ngx_log_error(NGX_LOG_DEBUG, c->log, 0, "ngx_tcp_cmd_handle");

    if (rev->timer_set) {
        ngx_del_timer(rev);
    }
    
    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "%s|%d|%s|client timed out", __FILE__, __LINE__, __FUNCTION__);
        c->timedout = 1;
        ngx_tcp_close_connection(c);
        return;
    }

    s->blocked = 0;

    n = c->recv(c, s->buffer->last, s->buffer->end - s->buffer->last);

    if (n == NGX_ERROR || n == 0) {
        ngx_tcp_close_connection(c);
        return;
    }

    ngx_add_timer(c->read, cscf->timeout);
    
    if (n > 0) {
        s->buffer->last += n;
    }

    if (n == NGX_AGAIN) {
        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
            ngx_tcp_session_internal_server_error((ngx_tcp_session_t *)s);
            return;
        }

        return;
    }

    while (1) {
        uint32_t buf_size = (uint32_t)(ngx_buf_size(s->buffer));
        uint32_t pkg_size = 0;
        ngx_tcp_cmd_pkghead_t *pkghead = NULL;

        if (buf_size < CMD_SESSION_PKG_HEAD_LEN) {
            ngx_buf_compact(s->buffer);
            break;
        }
        pkghead = (ngx_tcp_cmd_pkghead_t *)(s->buffer->pos);
        if (! ((ngx_tcp_cmd_session_t *)s)->pkghead_parsed) {
            ngx_tcp_cmd_pkghead_ntoh(pkghead);
            ((ngx_tcp_cmd_session_t *)s)->pkghead_parsed = 1;
        }
        pkg_size = pkghead->size;
        if (pkg_size > iscf->max_pkg_size) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0,
                "ngx_tcp_cmd_handle|pkg_size=%d|max_pkg_size=%d\n", 
                    pkg_size, iscf->max_pkg_size);
            ngx_tcp_close_connection(c);
            return;
        }
        if (pkg_size > (s->buffer->end - s->buffer->start)) {
            ngx_buf_t *new_buffer;
            new_buffer = ngx_create_temp_buf(c->pool, pkg_size);
            ngx_memcpy(new_buffer->pos, s->buffer->pos, buf_size);
            new_buffer->last = new_buffer->pos + buf_size;
            ngx_pfree(c->pool, s->buffer);
            s->buffer = new_buffer;
        }
        if (pkg_size > buf_size) {
            if (pkg_size > s->buffer->end - s->buffer->pos) {
                ngx_buf_compact(s->buffer);
            }
            break;
        }

        rc = ngx_tcp_cmd_parse_pkg(s);
        ((ngx_tcp_cmd_session_t *)s)->pkghead_parsed = 0;

        if (rc == NGX_ERROR) {
            ngx_tcp_close_connection(c);
            return;
        }
    }

    if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
        ngx_tcp_session_internal_server_error(s);
        return;
    }

    return;
}

ngx_buf_t *
ngx_buf_compact(ngx_buf_t *buffer)
{
    off_t buf_size = ngx_buf_size(buffer);
    if (buffer->pos != buffer->start) {
        ngx_memmove(buffer->start, buffer->pos, buf_size);
        buffer->pos = buffer->start;
        buffer->last = buffer->pos + buf_size;
    }

    return buffer;
}

ngx_int_t 
ngx_tcp_cmd_parse_pkg(ngx_tcp_session_t *s)
{
    ngx_tcp_cmd_session_t     *sub_s;
    ngx_tcp_cmd_pkghead_t     *pkghead;
	ngx_int_t                  rc = NGX_OK;

    sub_s = (ngx_tcp_cmd_session_t *)s;
    pkghead = (ngx_tcp_cmd_pkghead_t *)(sub_s->parent.buffer->pos);
	if (21 != pkghead->size)
	{
		cmd_pkg_handler_pt         h;
		h = ngx_tcp_cmd_lookup_pkg_handler(pkghead->cmd);
		if (h == NULL) {
			ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, 
            "ngx_tcp_cmd_parse_pkg|cmd=%d not found\n",
            pkghead->cmd);
			return NGX_ERROR;
		}
		rc = (*h)(& s->tcp_ctx, sub_s->parent.buffer->pos, pkghead->size);
	}

	sub_s->parent.buffer->pos += pkghead->size;
    return rc;
}
