
#include <ngx_tcp_io.h>

ngx_tcp_cmdpkg_filter_t recvpkg_filters;
ngx_tcp_cmdpkg_filter_t sendpkg_filters;

ngx_int_t
ngx_tcp_cmdpkg_filter_init(ngx_cycle_t *cycle, ngx_tcp_cmdpkg_filter_t *filter)
{
    if (NGX_OK != ngx_array_init(&filter->cmdpkg_filters,
                      cycle->pool,
                      4,
                      sizeof(cmdpkg_filter_pt))) {
        return NGX_ERROR;
    }
    filter->first_filter = NULL;
    filter->last_filter = NULL;

    return NGX_OK;
}


ngx_int_t
ngx_tcp_do_cmdpkg_filter(ngx_tcp_session_t *s, ngx_tcp_cmdpkg_filter_t *f,
    u_char **pkg, int *pkg_len)
{
    unsigned int      i;
    ngx_int_t         rc = NGX_OK;
    cmdpkg_filter_pt *filters;

    if (f->first_filter) {
        rc = (*f->first_filter)(&s->tcp_ctx, pkg, pkg_len);
        if (rc == NGX_ERROR)
            return rc;
    }
    filters = f->cmdpkg_filters.elts;
    for (i=0; i<f->cmdpkg_filters.nelts; ++i) {
        if (filters[i])
            rc = (*(filters[i]))(&s->tcp_ctx, pkg, pkg_len);
        if (rc == NGX_ERROR)
            return rc;
    }
    if (f->last_filter) {
        rc = (*f->last_filter)(&s->tcp_ctx, pkg, pkg_len);
        if (rc == NGX_ERROR)
            return rc;
    }

    return NGX_OK;
}


ngx_int_t
ngx_tcp_chain_writer(ngx_tcp_session_t *s)
{
    ngx_chain_writer_ctx_t *ctx;
    ngx_chain_t            *in;
    ngx_tcp_output_again_t *again_ptr;

    off_t                  size;
    ngx_chain_t            *cl;
    ngx_connection_t       *c;
  
    ctx = s->output_ctx->filter_ctx;
    in = s->output_buffer_chain;
    again_ptr = &s->output_again;
    c = ctx->connection;
    
    again_ptr->out_chain_arr[again_ptr->ix_w++] = in;
    again_ptr->ix_w &= (OUTPUT_CHAIN_AGAIN_SIZE - 1);
    
    //if output_again_arr is full, return error;
    if (again_ptr->ix_w == again_ptr->ix_r) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, 
            "ngx_tcp_chain_writer|output_again_arr is full|ix_w=%d|ix_r=%d", 
            again_ptr->ix_w, again_ptr->ix_r);
        return NGX_ERROR;
    }
  
    while (1) {
        if (NULL == again_ptr->out_chain_arr[again_ptr->ix_r]) {
        //  ix_r = 0;
        //  ix_w = 0;
            break;
        }
       
        ctx->out = again_ptr->out_chain_arr[again_ptr->ix_r];

        ngx_log_debug1(NGX_LOG_DEBUG_CORE, c->log, 0,
            "tcp chain writer in: %p", ctx->out);

        size = 0;
        for (cl = ctx->out; cl; cl = cl->next) {

    #if 1
            if (ngx_buf_size(cl->buf) == 0 && !ngx_buf_special(cl->buf)) {
                ngx_debug_point();
            }

    #endif

            size += ngx_buf_size(cl->buf);
        }

        if (size == 0 && !c->buffered) {
            again_ptr->out_chain_arr[again_ptr->ix_r] = NULL;
            again_ptr->ix_r++;
            again_ptr->ix_r &= (OUTPUT_CHAIN_AGAIN_SIZE - 1);
            continue;
        }

        again_ptr->out_chain_arr[again_ptr->ix_r] = 
            c->send_chain(c, 
                again_ptr->out_chain_arr[again_ptr->ix_r], ctx->limit);
        
        ctx->out = again_ptr->out_chain_arr[again_ptr->ix_r];
        ngx_log_debug1(NGX_LOG_DEBUG_CORE, c->log, 0,
                       "chain writer out: %p", ctx->out);

        if (ctx->out == NGX_CHAIN_ERROR) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0, 
                "ngx_tcp_chain_writer|out_chain_arr[%d]==NGX_CHAIN_ERROR", 
                again_ptr->ix_r);
            again_ptr->out_chain_arr[again_ptr->ix_r] = NULL;
            again_ptr->ix_r++;
            again_ptr->ix_r &= (OUTPUT_CHAIN_AGAIN_SIZE - 1);
            return NGX_ERROR;
        }

        if (ctx->out == NULL) {
            ctx->last = &ctx->out;
            
            if (!c->buffered) {
                again_ptr->ix_r++;
                again_ptr->ix_r &= (OUTPUT_CHAIN_AGAIN_SIZE - 1);
                //return NGX_OK;
                continue;
            }
        }
        
        ngx_log_error(NGX_LOG_DEBUG, c->log, 0,
            "ngx_tcp_chain_writer|again_ptr->out_chain_arr[%d] NGX_AGAIN", 
            again_ptr->ix_r);
        return NGX_AGAIN;
    }
    return NGX_OK;    
}

void
ngx_tcp_send(ngx_event_t *wev)
{
    ngx_int_t                  rc;
    ngx_connection_t          *c;
    ngx_tcp_session_t         *s;
    ngx_tcp_core_srv_conf_t   *cscf;

    c = wev->data;
    s = c->data;

    if (wev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "%s|%d|%s|client timed out",__FILE__, __LINE__, __FUNCTION__);
        c->timedout = 1;
        ngx_tcp_close_connection(c);
        return;
    }

    if (s->output_buffer_chain == NULL) {
        return;
    }

   // rc = s->output_ctx->output_filter(s->output_ctx->filter_ctx, 
                                      //s->output_buffer_chain);
    rc = s->output_ctx->output_filter(s);
    ngx_chain_update_chains(s->output_ctx->pool, 
                            &s->output_ctx->free, &s->output_ctx->busy, 
                            &s->output_buffer_chain, s->output_ctx->tag);
    s->output_buffer_chain = NULL;

    if (rc == NGX_OK || rc == NGX_DONE) {
        if (wev->timer_set) {
            ngx_del_timer(wev);
        }
        return;
    }

    if (rc == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, 
            "ngx_tcp_send|client=%V\n", &c->addr_text);
        ngx_tcp_close_connection(c);
        return;
    }

    /* rc == NGX_AGAIN */
    /*
    ngx_log_error(NGX_LOG_INFO, c->log, 0, 
                  "ngx_tcp_send|NGX_AGAIN|client=%V\n", &c->addr_text);
     */

    cscf = ngx_tcp_get_module_srv_conf(s, ngx_tcp_core_module);

    ngx_add_timer(c->write, cscf->timeout);

    if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
        ngx_tcp_close_connection(c);
        return;
    }
}


long 
ngx_tcp_send_data(ngx_tcp_ctx_t *ctx, const u_char *data, int len)
{
    ngx_chain_t                *out_chain;
    size_t                      data_copyed;
    ngx_chain_t                *cl;
    ngx_tcp_session_t          *s;
    ngx_connection_t           *c;

    s = ctx->ngx_tcp_session;
    c = s->connection;
    out_chain = ngx_tcp_chain_get_free_buf(s->output_ctx, len);
    if (NULL == out_chain) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, 
            "ngx_tcp_send_data|client=%V|out_chain==NULL\n", &c->addr_text);
        return -1;
    }

    data_copyed = 0;
    for (cl = out_chain; cl; cl = cl->next) {
        size_t to_copy = cl->buf->end - cl->buf->start;
        to_copy = ngx_min((len - data_copyed), to_copy);
        ngx_memcpy(cl->buf->pos, data + data_copyed, to_copy);
        data_copyed += to_copy;
        cl->buf->last += to_copy;
    }
    if (s->output_buffer_chain == NULL) {
        s->output_buffer_chain = out_chain;
    } else {
        cl = s->output_buffer_chain;
        while (cl->next != NULL) {
            cl = cl->next;
        }
        cl->next = out_chain;
    }

    ctx->pkg_send_count++;
    ngx_tcp_send(c->write);

    return 0;
}


long 
ngx_tcp_send_cmdpkg(ngx_tcp_ctx_t *ctx, u_char *data, int len)
{
    ngx_tcp_session_t *s;

    s = (ngx_tcp_session_t *)ctx->ngx_tcp_session;

    if (NGX_OK != ngx_tcp_do_cmdpkg_filter(s, &sendpkg_filters, &data, &len)) {
        return NGX_ERROR;
    }

    return ngx_tcp_send_data(ctx, data, len);
}

