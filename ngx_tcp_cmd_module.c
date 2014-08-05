
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_tcp.h>
#include <ngx_regex.h>
#include <ngx_tcp_cmd_module.h>
#include <dlfcn.h>
#include <ngx_map.h>

ngx_tcp_cmdso_mgr_t *cmdso_mgr;
ngx_map_t           *cmdso_conf;

static void *ngx_tcp_cmd_create_srv_conf(ngx_conf_t *cf);
static char *ngx_tcp_cmd_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child);

static ngx_int_t ngx_tcp_cmd_parse_ini_conf(ngx_cycle_t *cycle);
static ngx_int_t ngx_tcp_cmd_module_init(ngx_cycle_t *cycle);
static ngx_int_t ngx_tcp_cmd_process_init(ngx_cycle_t *cycle);
static void ngx_tcp_cmd_process_exit(ngx_cycle_t *cycle);
static char *
ngx_tcp_cmd_concat_filename(const char *cmdso_path, const char *fname);
static cmd_pkg_handler_pt 
ngx_tcp_cmd_lookup_pkg_handler_i(ngx_tcp_cmd_pkg_handler_mgr_t *mgr, uint32_t cmd);
static long
ngx_tcp_cmd_pkg_handler_add(void *cycle_param, 
                            uint32_t cmd_min, uint32_t cmd_max,
                            cmd_pkg_handler_pt h);
typedef ngx_int_t (*load_cmdso_process_pt) (ngx_cycle_t *, const char *);
static ngx_int_t
ngx_tcp_cmd_load_cmdso_process(ngx_cycle_t *cycle, 
                               const char *path, 
                               const char *fname, 
                               load_cmdso_process_pt h);
static ngx_int_t 
ngx_tcp_cmd_load_cmdso(ngx_cycle_t *cycle, const char *cmdso_path);
static ngx_int_t 
ngx_tcp_cmd_load_cmdso_i(ngx_cycle_t *cycle, const char *sofile);
static ngx_int_t 
ngx_tcp_cmd_keepalive_handler(ngx_tcp_ctx_t *ctx,
                              const u_char *pkg, 
                              int pkg_len);
static ngx_int_t 
ngx_tcp_cmd_tran_handler(ngx_tcp_ctx_t *ctx, const u_char *pkg, int pkg_len);


static ngx_tcp_protocol_t  ngx_tcp_cmd_protocol = {
    ngx_string("cmd"),
    { 110, 995, 0, 0 },
    NGX_TCP_CMD_PROTOCOL,

    ngx_tcp_cmd_create_session,
    ngx_tcp_cmd_init_session,
    ngx_tcp_cmd_finit_session,
    ngx_tcp_cmd_init_protocol,
    ngx_tcp_cmd_parse_pkg,

    ngx_string("-ERR internal server error" CRLF)
};


static ngx_command_t  ngx_tcp_cmd_commands[] = {

    { ngx_string("max_pkg_size"),
      NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_TCP_SRV_CONF_OFFSET,
      offsetof(ngx_tcp_cmd_srv_conf_t, max_pkg_size),
      NULL },

      ngx_null_command
};


static ngx_tcp_module_t  ngx_tcp_cmd_module_ctx = {
    &ngx_tcp_cmd_protocol,          /* protocol */

    NULL,                           /* create main configuration */
    NULL,                           /* init main configuration */

    ngx_tcp_cmd_create_srv_conf,    /* create server configuration */
    ngx_tcp_cmd_merge_srv_conf      /* merge server configuration */
};


ngx_module_t  ngx_tcp_cmd_module = {
    NGX_MODULE_V1,
    &ngx_tcp_cmd_module_ctx,      /* module context */
    ngx_tcp_cmd_commands,         /* module directives */
    NGX_TCP_MODULE,               /* module type */
    NULL,                         /* init master */
    ngx_tcp_cmd_module_init,      /* init module */
    ngx_tcp_cmd_process_init,     /* init process */
    NULL,                         /* init thread */
    NULL,                         /* exit thread */
    ngx_tcp_cmd_process_exit,     /* exit process */
    NULL,                         /* exit master */
    NGX_MODULE_V1_PADDING
};


typedef struct {
    ngx_rbtree_node_t node;
    uint32_t cmd_min;
    uint32_t cmd_max;
    cmd_pkg_handler_pt h;
} ngx_tcp_cmd_pkg_handler_node_t;


static void *
ngx_tcp_cmd_create_srv_conf(ngx_conf_t *cf)
{
    ngx_tcp_cmd_srv_conf_t  *iscf;

    iscf = ngx_pcalloc(cf->pool, sizeof(ngx_tcp_cmd_srv_conf_t));
    if (iscf == NULL) {
        return NULL;
    }
    iscf->max_pkg_size = NGX_CONF_UNSET_SIZE;

    return iscf;
}


static char *
ngx_tcp_cmd_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_tcp_cmd_srv_conf_t *prev = parent;
    ngx_tcp_cmd_srv_conf_t *conf = child;

    ngx_conf_merge_size_value(conf->max_pkg_size, 
                              prev->max_pkg_size, 1024 * 1024);

    return NGX_CONF_OK;
}


static ngx_int_t 
ngx_tcp_cmd_module_init(ngx_cycle_t *cycle)
{
    if (ngx_tcp_cmd_parse_ini_conf(cycle) != NGX_OK) {
        return NGX_ERROR;
    }
	
    ngx_map_test();

    return NGX_OK;
}


#define CMDSO_PATH_STR ngx_string("cmdso")
#define CMDSO_INI_FILE_STR ngx_string("cmdso.ini")
#define CMDSO_INI_FILE_LINE_MAXLEN 1024
#define CMDSO_INI_SECTION_PATTERN "^[\\s]*\\[(.*)\\][\\s]*$"
#define CMDSO_INI_LINE_PATTERN "^[\\s]*([\\S]*)[\\s]*=[\\s]*([\\S]*)[\\s]*$"
static ngx_int_t 
ngx_tcp_cmd_parse_ini_conf(ngx_cycle_t *cycle)
{
    ngx_str_t            cmdso_path = CMDSO_PATH_STR;
    ngx_str_t            cmdso_file = CMDSO_INI_FILE_STR;
    char                *path_file;
    FILE                *p_file;
    int                  lines;
    char                 line_buf[CMDSO_INI_FILE_LINE_MAXLEN];
#define PCRE_OVECTOR_SIZE 16
    int                  ovector[PCRE_OVECTOR_SIZE];
    ngx_regex_compile_t  re_section;
    ngx_regex_compile_t  re_line;
    int                  rc;
    ngx_str_t            ini_section = ngx_null_string;
    ngx_map_t           *section_map;

    cmdso_conf = ngx_map_create(NGX_MAP_STR_T, NGX_MAP_PTR_T, 
        cycle->pool, (ngx_palloc_pt)ngx_palloc, (ngx_pfree_pt)ngx_pfree);
    if (cmdso_conf == NULL) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0, 
            "ngx_tcp_cmd_parse_ini_conf|cmdso_conf == NULL\n");
        return NGX_ERROR;
    }

    /* the cmdso_path->data will end with '\0' */
    ngx_conf_full_name(cycle, &cmdso_path, 0);
    path_file = ngx_tcp_cmd_concat_filename((const char *)cmdso_path.data, 
        (const char *)cmdso_file.data);
    p_file = fopen(path_file, "r");
    free(path_file);
    if (p_file == NULL) {
        ngx_log_error(NGX_LOG_WARN, cycle->log, 0, 
            "ngx_tcp_cmd_parse_ini_conf|%V has'n %V\n", &cmdso_path, &cmdso_file);
        ngx_map_destroy(cmdso_conf);
        cmdso_conf = NULL;
        return NGX_OK;
    }

    ngx_memset(&re_section, 0, sizeof(ngx_regex_compile_t));
    re_section.pool = cycle->pool;
    re_section.pattern.data = (u_char *)CMDSO_INI_SECTION_PATTERN;
    re_section.pattern.len = sizeof(CMDSO_INI_SECTION_PATTERN) - 1;
    if (ngx_regex_compile(&re_section) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0, 
            "ngx_tcp_cmd_parse_ini_conf|pattern = %s|pcre_err is %V.\n", 
            CMDSO_INI_SECTION_PATTERN, &re_section.err);
        goto failed;
    }
    ngx_memset(&re_line, 0, sizeof(ngx_regex_compile_t));
    re_line.pool = cycle->pool;
    re_line.pattern.data = (u_char *)CMDSO_INI_LINE_PATTERN;
    re_line.pattern.len = sizeof(CMDSO_INI_LINE_PATTERN) - 1;
    if (ngx_regex_compile(&re_line) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0, 
            "ngx_tcp_cmd_parse_ini_conf|pattern = %s|pcre_err is %V.\n", 
            CMDSO_INI_LINE_PATTERN, &re_line.err);
        goto failed;
    }

    lines = 0;
    while (fgets(line_buf, CMDSO_INI_FILE_LINE_MAXLEN, p_file) != NULL
        && !feof(p_file)) {
        int str_len;
        int i = 0;
        ++lines;
        while(line_buf[i] 
            && (line_buf[i] == ' ' || line_buf[i] == '\t' 
                || line_buf[i] == '\n')) {
            ++i;
        }
        if (!line_buf[i] || line_buf[i] == '#')
            continue;
        rc = pcre_exec(re_section.regex->code, NULL, line_buf, ngx_strlen(line_buf), 
                       0, 0, ovector, PCRE_OVECTOR_SIZE);
        if (rc < 0) {
            goto __pcre_exec_after_ini_section__;
        }
        if (ini_section.data != NULL ) {
            free(ini_section.data);
            ini_section.data = NULL;
        }
        str_len = ovector[3] - ovector[2];
        ini_section.data = (u_char *)strndup(&line_buf[0] + ovector[2], str_len);
        ini_section.len = str_len;
        section_map = ngx_map_create(NGX_MAP_NGXSTR_T, NGX_MAP_NGXSTR_T, 
            cycle->pool, (ngx_palloc_pt)ngx_palloc, (ngx_pfree_pt)ngx_pfree); 
        if (cmdso_conf == NULL) {
            ngx_log_error(NGX_LOG_ERR, cycle->log, 0, 
                "ngx_tcp_cmd_parse_ini_conf|cmdso_conf == NULL\n");
            goto failed;
        }
        if (ngx_map_set_str_ptr(cmdso_conf, (const char *)ini_section.data, section_map) 
            != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, cycle->log, 0, 
                "ngx_tcp_cmd_parse_ini_conf|ngx_map_set_str_ptr %s\n", 
                ini_section.data);
            goto failed;
        }
        section_map = NULL;
        continue;

__pcre_exec_after_ini_section__:
        rc = pcre_exec(re_line.regex->code, NULL, line_buf, ngx_strlen(line_buf), 
                       0, 0, ovector, PCRE_OVECTOR_SIZE);
        if (rc < 0) {
            ngx_log_error(NGX_LOG_ERR, cycle->log, 0, 
                "ngx_tcp_cmd_parse_ini_conf|pcre_exec %s, line number %d\n",
                line_buf, lines);
            goto failed;
        }
        if (ini_section.data == NULL ) {
            ngx_log_error(NGX_LOG_ERR, cycle->log, 0, 
                "ngx_tcp_cmd_parse_ini_conf|no section line %s, line number %d\n",
                line_buf, lines);
            goto failed;
        }
        if (ngx_map_find_str_ptr(cmdso_conf, (const char *)ini_section.data, 
            (void **)&section_map) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, cycle->log, 0, 
                "ngx_tcp_cmd_parse_ini_conf|find section %s, line number %d\n",
                ini_section.data, lines);
            goto failed;
        }
        {
            ngx_str_t k,v;

            k.data = (u_char *)(line_buf + ovector[2]);
            k.len = ovector[3] - ovector[2];
            v.data = (u_char *)(line_buf + ovector[4]);
            v.len = ovector[5] - ovector[4];

            ngx_map_set_ngxstr_ngxstr(section_map, &k, &v);
        }
    } // end while
    fclose(p_file);

    return NGX_OK;

failed:
    if (ini_section.data != NULL ) {
        free(ini_section.data);
        ini_section.data = NULL;
    }
    if (p_file != NULL) {
        fclose(p_file);
        p_file = NULL;
    }
    return NGX_ERROR;
}

static ngx_int_t 
ngx_tcp_cmd_process_init(ngx_cycle_t *cycle)
{
    ngx_str_t            cmdso_path = CMDSO_PATH_STR;
    ngx_uint_t           i;
    ngx_tcp_cmdso_t     *cmdsos;
    ngx_tcp_cycle_ctx_t  *cycle_ctx;

    cmdso_mgr = ngx_pcalloc(cycle->pool, sizeof(ngx_tcp_cmdso_mgr_t));
    if (cmdso_mgr == NULL) {
        goto failed;
    }

	cycle_ctx = ngx_pcalloc(cycle->pool, sizeof(ngx_tcp_cycle_ctx_t));
	if (NULL == cycle_ctx) {
		goto failed;
	}
	
	cycle_ctx->conf_get_str = (ngx_tcp_conf_get_str_pt)ngx_tcp_cmd_conf_get_str;
	cycle_ctx->tcp_log_t.log = cycle->log;
        cycle_ctx->tcp_log_t.log_level = cycle->log->log_level;
	cycle_ctx->tcp_log_t.log_error=(ngx_tcp_log_error_pt)ngx_log_error_core;

    ngx_rbtree_init(&cmdso_mgr->pkg_handler_mgr.rbtree, 
                    &cmdso_mgr->pkg_handler_mgr.sentinel, 
                    ngx_rbtree_insert_value);
    if (NGX_OK != ngx_array_init(&cmdso_mgr->cmdsos,
                                 cycle->pool,
                                 4, 
                                 sizeof(ngx_tcp_cmdso_t))) {
        goto failed;
    }
    if (NGX_OK != ngx_tcp_cmd_pkg_handler_add(cycle, 
                                        NGX_TCP_CMD_KEEPALIVE,
                                        NGX_TCP_CMD_KEEPALIVE,
                                        ngx_tcp_cmd_keepalive_handler)) {
        goto failed;
    }
    if (NGX_OK != ngx_tcp_cmd_pkg_handler_add(cycle, 
                                        NGX_TCP_CMD_TRAN,
                                        NGX_TCP_CMD_TRAN,
                                        ngx_tcp_cmd_tran_handler)) {
        goto failed;
    }

    /* the cmdso_path->data will end with '\0' */
    ngx_conf_full_name(cycle, &cmdso_path, 0);
    if (NGX_OK != ngx_tcp_cmd_load_cmdso(cycle, 
                                         (const char *) cmdso_path.data)) {
        goto failed;
    }
    cmdsos = cmdso_mgr->cmdsos.elts;
    for (i=0; i < cmdso_mgr->cmdsos.nelts; ++i) {
        if (cmdsos[i].cmdso_load(cycle, ngx_tcp_cmd_pkg_handler_add, i, cycle_ctx)
            != NGX_OK) {
            goto failed;
        }
    }

    return NGX_OK;

failed:
    return NGX_ERROR;
}


static ngx_int_t 
ngx_tcp_cmd_load_cmdso(ngx_cycle_t *cycle, const char *cmdso_path)
{
    struct dirent       **namelist;
    int                   n;
    ngx_int_t             rc, ret;

    ret = rc = NGX_OK;
    n = scandir(cmdso_path, &namelist, NULL, alphasort);
    if (n < 0) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0, 
            "ngx_tcp_cmd_load_cmdso|errno=%d\n", errno);
        return NGX_ERROR;
    } else {
        while (n--) {
            struct dirent *ent = namelist[n];
            if (ent->d_type & DT_DIR) {
                 if(ngx_strcmp(ent->d_name, ".") == 0 
                    || ngx_strcmp(ent->d_name, "..") == 0) {
                     free(ent);
                     continue;
                 }
                 rc = ngx_tcp_cmd_load_cmdso_process(cycle, 
                         cmdso_path, 
                         ent->d_name, 
                         ngx_tcp_cmd_load_cmdso);
                 if (rc != NGX_OK) {
                     ret = rc;
                 }
            }
            if (ent->d_type & DT_REG || ent->d_type == DT_UNKNOWN) {
                 size_t filename_len = ngx_strlen(ent->d_name);
                 if (filename_len < 3 || ent->d_name[filename_len - 1] != 'o'
                     || ent->d_name[filename_len - 2] != 's'
                     || ent->d_name[filename_len - 3] != '.') {
                     free(ent);
                     ngx_log_error(NGX_LOG_ERR, cycle->log, 0, 
                         "ngx_tcp_cmd_load_cmdso|don't load %s,"
                         " file name must end with \".so\"\n", ent->d_name);
                     continue;
                 }
                 rc = ngx_tcp_cmd_load_cmdso_process(cycle, 
                         cmdso_path, 
                         ent->d_name, 
                         ngx_tcp_cmd_load_cmdso_i);
                 if (rc != NGX_OK) {
                     ret = rc;
                 }
            }
            free(ent);
        }
        free(namelist);
    }

    return ret;
}


static ngx_int_t
ngx_tcp_cmd_load_cmdso_process(ngx_cycle_t *cycle, 
                               const char *path, 
                               const char *fname, 
                               load_cmdso_process_pt h)
{
    char           *new_path;
    ngx_int_t       ret;

    new_path = ngx_tcp_cmd_concat_filename(path, fname);
    if (new_path == NULL) {
        return NGX_ERROR;
    }
    ret = (*h)(cycle, new_path);
    free(new_path);

    return ret;
}


static ngx_int_t 
ngx_tcp_cmd_load_cmdso_i(ngx_cycle_t *cycle, const char *sofile)
{
    void                  *handle;
    ngx_tcp_cmdso_t       *cmdso;
    cmdso_load_pt          soload;
    cmdso_unload_pt        sounload;
    cmdso_sess_init_pt     so_sess_init;
    cmdso_sess_finit_pt    so_sess_finit;

    handle = dlopen(sofile, RTLD_NOW);
    if (! handle) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0, 
            "ngx_tcp_cmd_load_cmdso_i|dlopen %s|errno=%d|errmsg=%s\n", sofile, errno, dlerror());
        goto failed;
    }

    dlerror();
    *(void **) (&soload) = dlsym(handle, CMDSO_LOAD);
    if (soload == NULL) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0, 
            "ngx_tcp_cmd_load_cmdso_i|dlsym %s:%s|errno=%d|errmsg=%s\n", 
                sofile, CMDSO_LOAD, errno);
        goto failed;
    }
    *(void **) (&sounload) = dlsym(handle, CMDSO_UNLOAD);
    if (sounload == NULL) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0, 
            "ngx_tcp_cmd_load_cmdso_i|dlsym %s:%s|errno=%d\n", 
                sofile, CMDSO_UNLOAD, errno);
        goto failed;
    }
    *(void **) (&so_sess_init) = dlsym(handle, CMDSO_SESS_INIT);
    if (so_sess_init == NULL) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0, 
            "ngx_tcp_cmd_load_cmdso_i|dlsym %s:%s|errno=%d\n", 
                sofile, CMDSO_SESS_INIT, errno);
        goto failed;
    }
    *(void **) (&so_sess_finit) = dlsym(handle, CMDSO_SESS_FINIT);
    if (so_sess_finit == NULL) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0, 
            "ngx_tcp_cmd_load_cmdso_i|dlsym %s:%s|errno=%d\n", 
                sofile, CMDSO_SESS_FINIT, errno);
        goto failed;
    }

    cmdso = (ngx_tcp_cmdso_t *) ngx_array_push(&cmdso_mgr->cmdsos);
    cmdso->handle = handle;
    cmdso->cmdso_load = soload;
    cmdso->cmdso_unload = sounload;
    cmdso->cmdso_sess_init = so_sess_init;
    cmdso->cmdso_sess_finit = so_sess_finit;

    ngx_log_error(NGX_LOG_INFO, cycle->log, 0, 
        "ngx_tcp_cmd_load_cmdso_i|load %s\n", sofile);


    return NGX_OK;

failed:
    if (handle != NULL) {
        dlclose(handle);
    }
    return NGX_ERROR;
}


static char *
ngx_tcp_cmd_concat_filename(const char *cmdso_path, const char *fname)
{
    int new_path_len;
    char *new_path;

    new_path_len = ngx_strlen(cmdso_path) + ngx_strlen(fname) + 2;
    new_path = (char *) malloc(new_path_len);
    ngx_memset(new_path, 0, new_path_len);
    if (new_path == NULL)
        return NULL;
    ngx_sprintf((u_char *)new_path, "%s/%s", cmdso_path, fname);

    return new_path;
}


static long
ngx_tcp_cmd_pkg_handler_add(void *cycle_param, 
                                uint32_t cmd_min,  uint32_t cmd_max,
                                cmd_pkg_handler_pt h)
{
    ngx_cycle_t *cycle;
    cmd_pkg_handler_pt h_found;
    ngx_tcp_cmd_pkg_handler_node_t *h_node;

    cycle = (ngx_cycle_t *) cycle_param;
    h_found = ngx_tcp_cmd_lookup_pkg_handler(cmd_min);
    if (h_found != NULL) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0, 
            "ngx_tcp_cmd_pkg_handler_add h_found|cmd_min=%d|cmd_max=%d\n", 
                cmd_min, cmd_max);
        return NGX_ERROR;
    }
    h_node = ngx_pcalloc(cycle->pool, sizeof(ngx_tcp_cmd_pkg_handler_node_t));
    if (h_node == NULL) {
        goto failed;
    }
    h_node->node.key = cmd_min;
    h_node->cmd_min = cmd_min;
    h_node->cmd_max = cmd_max;
    h_node->h = h;
    ngx_rbtree_insert(&cmdso_mgr->pkg_handler_mgr.rbtree, &h_node->node);

    return NGX_OK;

failed:
    return NGX_ERROR;
}


cmd_pkg_handler_pt
ngx_tcp_cmd_lookup_pkg_handler(uint32_t cmd)
{
    return ngx_tcp_cmd_lookup_pkg_handler_i(&cmdso_mgr->pkg_handler_mgr, cmd);
}


static cmd_pkg_handler_pt
ngx_tcp_cmd_lookup_pkg_handler_i(ngx_tcp_cmd_pkg_handler_mgr_t *mgr, 
                                     uint32_t cmd)
{
    ngx_tcp_cmd_pkg_handler_node_t *h_node;
    ngx_rbtree_node_t  *node, *sentinel;
    ngx_rbtree_key_t key = cmd;

    node = mgr->rbtree.root;
    sentinel = mgr->rbtree.sentinel;
    while (node != sentinel) {
        h_node = (ngx_tcp_cmd_pkg_handler_node_t *) node;
        if (cmd >= h_node->cmd_min && cmd <= h_node->cmd_max) {
            return ((ngx_tcp_cmd_pkg_handler_node_t *)node)->h;
        }
        if (key < node->key) {
            node = node->left;
            continue;
        }

        if (key > node->key) {
            node = node->right;
            continue;
        }

        return ((ngx_tcp_cmd_pkg_handler_node_t *)node)->h;
    }

    return NULL;
}


static void
ngx_tcp_cmd_process_exit(ngx_cycle_t *cycle)
{
    ngx_tcp_cmdso_t    *cmdsos;
    unsigned int        i;

    cmdsos = cmdso_mgr->cmdsos.elts;
    for (i=0; i < cmdso_mgr->cmdsos.nelts; ++i) {
        if (cmdsos[i].cmdso_unload(cycle) != NGX_OK) {
          ngx_log_error(NGX_LOG_ERR, cycle->log, 0, 
              "ngx_tcp_cmd_process_exit|slot=%d\n", i);
        }
    }
}


static ngx_int_t 
ngx_tcp_cmd_keepalive_handler(ngx_tcp_ctx_t *ctx, 
                              const u_char *pkg, 
                              int pkg_len)
{
    ngx_tcp_cmd_session_t    *s;
    ngx_connection_t         *c;
    ngx_tcp_cmd_pkghead_t    *pkghead;

    s = ctx->ngx_tcp_session;
    c = s->parent.connection;
    pkghead = (ngx_tcp_cmd_pkghead_t *)(pkg);
    ngx_log_error(NGX_LOG_ERR, c->log, 0, 
        "ngx_tcp_cmd_keepalive_handler|pkg_size=%d\n", pkghead->size);

    return NGX_OK;
}

static ngx_int_t
ngx_tcp_cmd_tran_handler(ngx_tcp_ctx_t *ctx, const u_char *pkg, int pkg_len)
{
    ngx_tcp_cmd_pkghead_t       *pkghead;
    ngx_tcp_cmd_pkgtran_t       *pkgtran;
    uint32_t                     pkg_size;
    ngx_tcp_cmd_session_t       *s;
    ngx_connection_t            *c;
    ngx_tcp_cmd_session_t       *dest_s;
    ngx_tcp_core_main_conf_t    *cmcf;
    socketfd_info_t             *socketfd_info;

    s = ctx->ngx_tcp_session;
    c = s->parent.connection;
    if (ngx_rstrncmp((u_char *)"unix:", c->addr_text.data, sizeof("unix:") - 1) != 0) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, 
            "ngx_tcp_cmd_tran_handler|cli=%V\n", &c->addr_text);
        return NGX_OK;
    }
    cmcf = ngx_tcp_get_module_main_conf(((ngx_tcp_session_t *)s), 
                                            ngx_tcp_core_module);
    pkghead = (ngx_tcp_cmd_pkghead_t *)(pkg);
    pkgtran = (ngx_tcp_cmd_pkgtran_t *)(pkghead + 1);
    pkg_size = pkgtran->data_size;
    socketfd_info = cmcf->socketfd_shm->info->socketfd_info + pkgtran->dest_fd;
    dest_s = (ngx_tcp_cmd_session_t *)(socketfd_info->tag);
    if (dest_s == NULL) {
        ngx_log_error(NGX_LOG_ERR, s->parent.connection->log, 0, 
            "ngx_tcp_cmd_tran_handler|dest_s=NULL|dest_fd=%d|dest_pid=%d\n",
                pkgtran->dest_fd, pkgtran->dest_pid);
        return NGX_OK;
    }
    if (dest_s->parent.connection == NULL || pkgtran->dest_fd <= 2) {
        ngx_log_error(NGX_LOG_ERR, s->parent.connection->log, 0, 
            "ngx_tcp_cmd_tran_handler|dest_c=%p|dest_fd=%d\n",
                dest_s->parent.connection, pkgtran->dest_fd);
        return NGX_OK;
    }
    if (ngx_pid != pkgtran->dest_pid 
      || ngx_process_slot != socketfd_info->listening_unix_info_i
      || pkgtran->dest_fd != dest_s->parent.connection->fd) {
        ngx_log_error(NGX_LOG_ERR, s->parent.connection->log, 0, 
            "ngx_tcp_cmd_tran_handler|conn fd=%d|dest_fd=%d"
            "|ngx_process_slot=%d|listening_unix_info_i=%d"
            "|dest_pid=%d|ngx_pid=%d\n", 
                 dest_s->parent.connection->fd, pkgtran->dest_fd, 
                 ngx_process_slot, socketfd_info->listening_unix_info_i,
                 pkgtran->dest_pid, ngx_pid);
        return NGX_OK;
    }
    
    ngx_tcp_send_data(&dest_s->parent.tcp_ctx, pkgtran->data, pkg_size);

    return NGX_OK;
}

ngx_int_t 
ngx_tcp_cmd_conf_get_str(const char *section, const char *k, char **v)
{
    ngx_map_t *section_map;
    ngx_str_t  fk, *fv;

    if (cmdso_conf == NULL) {
        return NGX_ERROR;
    }

    if (ngx_map_find_str_ptr(cmdso_conf, section, (void **)&section_map)
        != NGX_OK) {
        return NGX_ERROR;
    }

    fk.data = (u_char *)k;
    fk.len = ngx_strlen(k);
    if (ngx_map_find_ngxstr_ngxstr(section_map, &fk, &fv)
        != NGX_OK) {
        return NGX_ERROR;
    }

    *v = (char *)fv->data;

    return NGX_OK;
}

