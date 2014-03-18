#include <ngx_map.h>
#include <assert.h>

struct ngx_map_s {
    ngx_rbtree_t             rbtree;
    ngx_rbtree_node_t        sentinel;

    u_char                   k_type;
    u_char                   v_type;

    void                    *pool;
    ngx_palloc_pt            palloc;
    ngx_pfree_pt             pfree;
};

typedef struct {
    ngx_rbtree_node_t  node;
    u_char             data[0];
} ngx_map_node_t;

/* pool == NULL use malloc and free */
static void ngx_map_free_node(ngx_map_t *ngx_map, ngx_rbtree_node_t *node);
static void *map_alloc(void *pool, ngx_palloc_pt palloc, size_t size);
static void map_free(void *pool, ngx_pfree_pt pfree, void *ptr);
static ngx_map_node_t *ngx_map_find_uintptr(ngx_map_t *ngx_map, uintptr_t k);
static ngx_map_node_t *ngx_map_find_ptr(ngx_map_t *ngx_map, void *k);
static ngx_map_node_t *ngx_map_find_str(ngx_map_t *ngx_map, const char *k, 
    size_t k_len);
static ngx_map_node_t *ngx_map_find_ngxstr(ngx_map_t *ngx_map, 
    const ngx_str_t *k);
static void ngx_rbtree_set_key_ptr(ngx_rbtree_node_t *root,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);
static void ngx_rbtree_set_key_str(ngx_rbtree_node_t *root, 
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);
static void ngx_rbtree_set_key_ngxstr(ngx_rbtree_node_t *root, 
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);


ngx_map_t *
ngx_map_create(u_char key_type, u_char val_type, void *pool, 
    ngx_palloc_pt palloc, ngx_pfree_pt pfree)
{
    ngx_map_t  *m;

    m = NULL;
    if (key_type < NGX_MAP_TYPE_MIN || key_type > NGX_MAP_TYPE_MAX
        || val_type < NGX_MAP_TYPE_MIN || val_type > NGX_MAP_TYPE_MAX ) {
        goto failed;
    }

    m = map_alloc(pool, palloc, sizeof(ngx_map_t));
    if (m == NULL) {
        goto failed;
    }
    ngx_memset(m, 0, sizeof(ngx_map_t));
    m->k_type = key_type;
    m->v_type = val_type;
    m->pool = pool;
    m->palloc = palloc;
    m->pfree = pfree;

    if (key_type == NGX_MAP_UINTPTR_T) {
        ngx_rbtree_init(&m->rbtree, &m->sentinel, ngx_rbtree_insert_value);
    }
    if (key_type == NGX_MAP_PTR_T) {
        ngx_rbtree_init(&m->rbtree, &m->sentinel, ngx_rbtree_set_key_ptr);
    }
    if (key_type == NGX_MAP_STR_T) {
        ngx_rbtree_init(&m->rbtree, &m->sentinel, ngx_rbtree_set_key_str);
    }
    if (key_type == NGX_MAP_NGXSTR_T) {
        ngx_rbtree_init(&m->rbtree, &m->sentinel, ngx_rbtree_set_key_ngxstr);
    }

    return m;

failed:
    if (m != NULL) {
        map_free(pool, pfree, m);
        m = NULL;
    }
    return NULL;
}

void 
ngx_map_destroy(ngx_map_t *ngx_map)
{
    ngx_rbtree_node_t *root, *sentinel;

    root = ngx_map->rbtree.root;
    sentinel = ngx_map->rbtree.sentinel;

    if(root != sentinel) {
        ngx_map_free_node(ngx_map, root);
    }
    map_free(ngx_map->pool, ngx_map->pfree, ngx_map);
}

static void
ngx_map_free_node(ngx_map_t *ngx_map, ngx_rbtree_node_t *node)
{
    ngx_rbtree_node_t       *sentinel;

    sentinel = ngx_map->rbtree.sentinel;
    if (node->left != sentinel)
        ngx_map_free_node(ngx_map, node->left);
    if (node->right != sentinel)
        ngx_map_free_node(ngx_map, node->right);
    map_free(ngx_map->pool, ngx_map->pfree, node);
}

ngx_int_t 
ngx_map_set_uintptr_uintptr(ngx_map_t *ngx_map, uintptr_t k, uintptr_t v)
{
    ngx_map_node_t *m_node;

    m_node = map_alloc(ngx_map->pool, ngx_map->palloc, 
                       sizeof(ngx_map_node_t) + sizeof(uintptr_t));
    if (m_node == NULL) {
        return NGX_ERROR;
    }
    m_node->node.key = k;
    *((uintptr_t *) m_node->data) = v;
    ngx_rbtree_insert(&ngx_map->rbtree, &m_node->node);

    return NGX_OK;
}

ngx_int_t 
ngx_map_set_uintptr_ptr(ngx_map_t *ngx_map, uintptr_t k, void *v)
{
    ngx_map_node_t *m_node;

    m_node = map_alloc(ngx_map->pool, ngx_map->palloc, 
                       sizeof(ngx_map_node_t) + sizeof(void *));
    if (m_node == NULL) {
        return NGX_ERROR;
    }
    m_node->node.key = k;
    *((void **)(&m_node->data[0])) = v;
    ngx_rbtree_insert(&ngx_map->rbtree, &m_node->node);

    return NGX_OK;
}

ngx_int_t 
ngx_map_set_uintptr_str(ngx_map_t *ngx_map, uintptr_t k, const char *v)
{
    ngx_map_node_t *m_node;
    size_t          v_len;

    v_len = ngx_strlen(v);
    m_node = map_alloc(ngx_map->pool, ngx_map->palloc, 
                       sizeof(ngx_map_node_t) + v_len + 1);
    if (m_node == NULL) {
        return NGX_ERROR;
    }
    m_node->node.key = k;
    ngx_memcpy(m_node->data, (u_char *)v, v_len);
    m_node->data[v_len] = '\0';
    ngx_rbtree_insert(&ngx_map->rbtree, &m_node->node);

    return NGX_OK;
}

ngx_int_t 
ngx_map_set_uintptr_ngxstr(ngx_map_t *ngx_map, uintptr_t k, ngx_str_t *v)
{
    ngx_map_node_t *m_node;
    ngx_str_t      *str_val;

    m_node = map_alloc(ngx_map->pool, ngx_map->palloc, 
                       sizeof(ngx_map_node_t) + sizeof(ngx_str_t) + v->len + 1);
    if (m_node == NULL) {
        return NGX_ERROR;
    }
    m_node->node.key = k;
    str_val = (ngx_str_t *) m_node->data;
    str_val->data = m_node->data + sizeof(ngx_str_t);
    ngx_memcpy(str_val->data, v->data, v->len);
    str_val->data[v->len] = '\0';
    str_val->len = v->len;
    ngx_rbtree_insert(&ngx_map->rbtree, &m_node->node);

    return NGX_OK;
}


ngx_int_t 
ngx_map_find_uintptr_uintptr(ngx_map_t *ngx_map, uintptr_t k, uintptr_t *v)
{
    ngx_map_node_t *m_node;

    m_node = ngx_map_find_uintptr(ngx_map, k);
    if (m_node == NULL) {
        return NGX_ERROR;
    }
    *v = *((uintptr_t *)m_node->data);

    return NGX_OK;
}

ngx_int_t 
ngx_map_find_uintptr_ptr(ngx_map_t *ngx_map, uintptr_t k, void **v)
{
    ngx_map_node_t *m_node;

    m_node = ngx_map_find_uintptr(ngx_map, k);
    if (m_node == NULL) {
        return NGX_ERROR;
    }
    *v = *((void **)&m_node->data[0]);

    return NGX_OK;
}

ngx_int_t 
ngx_map_find_uintptr_str(ngx_map_t *ngx_map, uintptr_t k, char **v)
{
    ngx_map_node_t *m_node;

    m_node = ngx_map_find_uintptr(ngx_map, k);
    if (m_node == NULL) {
        return NGX_ERROR;
    }
    *v = (char *)(&m_node->data[0]);

    return NGX_OK;
}

ngx_int_t 
ngx_map_find_uintptr_t_ngxstr(ngx_map_t *ngx_map, uintptr_t k, ngx_str_t **v)
{
    return ngx_map_find_uintptr_str(ngx_map, k, (char **)v);
}

ngx_int_t 
ngx_map_set_ptr_uintptr(ngx_map_t *ngx_map, void *k, uintptr_t v)
{
    uintptr_t        hash;
    ngx_map_node_t *m_node;

    m_node = map_alloc(ngx_map->pool, ngx_map->palloc, 
        sizeof(ngx_map_node_t) + sizeof(void *) + sizeof(uintptr_t));
    if (m_node == NULL) {
        return NGX_ERROR;
    }
    hash = ngx_crc32_long(k, sizeof(void *));
    m_node->node.key = hash;
    *((void **)&m_node->data[0]) = k;
    *((uintptr_t *)(m_node->data + sizeof(void *))) = v;
    ngx_rbtree_insert(&ngx_map->rbtree, &m_node->node);

    return NGX_OK;
}

ngx_int_t 
ngx_map_set_ptr_ptr(ngx_map_t *ngx_map, void *k, void *v)
{
    uintptr_t        hash;
    ngx_map_node_t *m_node;

    m_node = map_alloc(ngx_map->pool, ngx_map->palloc, 
        sizeof(ngx_map_node_t) + sizeof(void *) + sizeof(void *));
    if (m_node == NULL) {
        return NGX_ERROR;
    }
    hash = ngx_crc32_long(k, sizeof(void *));
    m_node->node.key = hash;
    *((void **)&m_node->data) = k;
    *((void **)(&m_node->data[sizeof(void *)])) = v;
    ngx_rbtree_insert(&ngx_map->rbtree, &m_node->node);

    return NGX_OK;
}

ngx_int_t 
ngx_map_set_ptr_str(ngx_map_t *ngx_map, void *k, const char *v)
{
    uintptr_t        hash;
    ngx_map_node_t *m_node;
    size_t          v_len;

    v_len = ngx_strlen(v);
    m_node = map_alloc(ngx_map->pool, ngx_map->palloc, 
        sizeof(ngx_map_node_t) + sizeof(void *) + v_len + 1);
    if (m_node == NULL) {
        return NGX_ERROR;
    }
    hash = ngx_crc32_long(k, sizeof(void *));
    m_node->node.key = hash;
    *((void **)&m_node->data) = k;
    ngx_memcpy(m_node->data + sizeof(void *), (u_char *)v, v_len);
    (m_node->data + sizeof(void *))[v_len] = '\0';
    ngx_rbtree_insert(&ngx_map->rbtree, &m_node->node);

    return NGX_OK;
}

ngx_int_t 
ngx_map_set_ptr_ngxstr(ngx_map_t *ngx_map, void *k, ngx_str_t *v)
{
    uintptr_t        hash;
    ngx_map_node_t *m_node;
    size_t          node_data_len;
    ngx_str_t      *str_val;

    node_data_len = sizeof(ngx_map_node_t) + sizeof(void *) 
        + sizeof(ngx_str_t) + v->len + 1;
    m_node = map_alloc(ngx_map->pool, ngx_map->palloc, node_data_len);
    if (m_node == NULL) {
        return NGX_ERROR;
    }
    hash = ngx_crc32_long(k, sizeof(void *));
    m_node->node.key = hash;
    *((void **)&m_node->data) = k;
    str_val = (ngx_str_t *)(m_node->data + sizeof(void *));
    str_val->data = (u_char *)(str_val + 1);
    ngx_memcpy(str_val->data, v->data, v->len);
    str_val->data[v->len] = '\0';
    str_val->len = v->len;
    ngx_rbtree_insert(&ngx_map->rbtree, &m_node->node);

    return NGX_OK;
}

ngx_int_t 
ngx_map_find_ptr_uintptr(ngx_map_t *ngx_map, void *k, uintptr_t *v)
{
    ngx_map_node_t *m_node;

    m_node = ngx_map_find_ptr(ngx_map, k);
    if (m_node == NULL) {
        return NGX_ERROR;
    }

    *v = *((uintptr_t *) (m_node->data + sizeof(void *)));

    return NGX_OK;
}

ngx_int_t 
ngx_map_find_ptr_ptr(ngx_map_t *ngx_map, void *k, void **v)
{
    ngx_map_node_t *m_node;

    m_node = ngx_map_find_ptr(ngx_map, k);
    if (m_node == NULL) {
        return NGX_ERROR;
    }

    *v = *((void **)&m_node->data[sizeof(void *)]);

    return NGX_OK;
}

ngx_int_t 
ngx_map_find_ptr_str(ngx_map_t *ngx_map, void *k, char **v)
{
    ngx_map_node_t *m_node;

    m_node = ngx_map_find_ptr(ngx_map, k);
    if (m_node == NULL) {
        return NGX_ERROR;
    }

    *v = (char *)(&m_node->data[sizeof(void *)]);

    return NGX_OK;
}

ngx_int_t 
ngx_map_find_ptr_ngxstr(ngx_map_t *ngx_map, void *k, ngx_str_t **v)
{
    return ngx_map_find_ptr_str(ngx_map, k, (char **)v);
}



ngx_int_t 
ngx_map_set_str_uintptr(ngx_map_t *ngx_map, const char *k, uintptr_t v)
{
    uintptr_t        hash;
    ngx_map_node_t *m_node;
    size_t          k_len;

    k_len = ngx_strlen(k);
    m_node = map_alloc(ngx_map->pool, ngx_map->palloc, 
        sizeof(ngx_map_node_t) + k_len + 1 + sizeof(uintptr_t));
    if (m_node == NULL) {
        return NGX_ERROR;
    }
    hash = ngx_crc32_long((u_char *)k, k_len);
    m_node->node.key = hash;
    ngx_memcpy(m_node->data, (u_char *)k, k_len);
    m_node->data[k_len] = '\0';
    *((uintptr_t *)(m_node->data + k_len + 1)) = v;
    ngx_rbtree_insert(&ngx_map->rbtree, &m_node->node);

    return NGX_OK;
}

ngx_int_t 
ngx_map_set_str_ptr(ngx_map_t *ngx_map, const char *k, void *v)
{
    uintptr_t        hash;
    ngx_map_node_t *m_node;
    size_t          k_len;

    k_len = ngx_strlen(k);
    m_node = map_alloc(ngx_map->pool, ngx_map->palloc, 
        sizeof(ngx_map_node_t) + k_len + 1 + sizeof(void *));
    if (m_node == NULL) {
        return NGX_ERROR;
    }
    hash = ngx_crc32_long((u_char *)k, k_len);
    m_node->node.key = hash;
    ngx_memcpy(m_node->data, (u_char *)k, k_len);
    m_node->data[k_len] = '\0';
    *((void **)&m_node->data[k_len + 1]) = v;
    ngx_rbtree_insert(&ngx_map->rbtree, &m_node->node);

    return NGX_OK;
}

ngx_int_t 
ngx_map_set_str_str(ngx_map_t *ngx_map, const char *k, const char *v)
{
    uintptr_t        hash;
    ngx_map_node_t *m_node;
    size_t          k_len;
    size_t          v_len;

    k_len = ngx_strlen(k);
    v_len = ngx_strlen(v);
    m_node = map_alloc(ngx_map->pool, ngx_map->palloc, 
        sizeof(ngx_map_node_t) + k_len + 1 + v_len + 1);
    if (m_node == NULL) {
        return NGX_ERROR;
    }
    hash = ngx_crc32_long((u_char *)k, k_len);
    m_node->node.key = hash;
    ngx_memcpy(m_node->data, (u_char *)k, k_len);
    m_node->data[k_len] = '\0';
    ngx_memcpy(m_node->data + k_len + 1, (u_char *)v, v_len);
    m_node->data[k_len + 1 + v_len] = '\0';
    ngx_rbtree_insert(&ngx_map->rbtree, &m_node->node);

    return NGX_OK;
}

ngx_int_t 
ngx_map_set_str_ngxstr(ngx_map_t *ngx_map, const char *k, ngx_str_t *v)
{
    uintptr_t        hash;
    ngx_map_node_t *m_node;
    size_t          k_len;
    size_t          node_data_len;
    ngx_str_t      *str_val;

    k_len = ngx_strlen(k);
    node_data_len = sizeof(ngx_map_node_t) + k_len + 1 
        + sizeof(ngx_str_t) + v->len + 1;
    m_node = map_alloc(ngx_map->pool, ngx_map->palloc, node_data_len);
    if (m_node == NULL) {
        return NGX_ERROR;
    }
    hash = ngx_crc32_long((u_char *)k, k_len);
    m_node->node.key = hash;
    ngx_memcpy(m_node->data, (u_char *)k, k_len);
    m_node->data[k_len] = '\0';
    str_val = (ngx_str_t *)(m_node->data + k_len + 1);
    *((void **)(&str_val->data)) = str_val + 1;
    ngx_memcpy(str_val->data, v->data, v->len);
    str_val->data[v->len] = '\0';
    ngx_rbtree_insert(&ngx_map->rbtree, &m_node->node);

    return NGX_OK;
}

ngx_int_t 
ngx_map_find_str_uintptr(ngx_map_t *ngx_map, const char *k, uintptr_t *v)
{
    size_t          k_len;
    ngx_map_node_t *m_node;

    k_len = ngx_strlen(k);
    m_node = ngx_map_find_str(ngx_map, k, k_len);
    if (m_node == NULL) {
        return NGX_ERROR;
    }
    *v = *((uintptr_t *)(m_node->data + k_len + 1));

    return NGX_OK;
}

ngx_int_t 
ngx_map_find_str_ptr(ngx_map_t *ngx_map, const char *k, void **v)
{
    size_t          k_len;
    ngx_map_node_t *m_node;

    k_len = ngx_strlen(k);
    m_node = ngx_map_find_str(ngx_map, k, k_len);
    if (m_node == NULL) {
        return NGX_ERROR;
    }
    *v = *((void **)&m_node->data[k_len + 1]);

    return NGX_OK;
}

ngx_int_t 
ngx_map_find_str_str(ngx_map_t *ngx_map, const char *k, char **v)
{
    size_t          k_len;
    ngx_map_node_t *m_node;

    k_len = ngx_strlen(k);
    m_node = ngx_map_find_str(ngx_map, k, k_len);
    if (m_node == NULL) {
        return NGX_ERROR;
    }
    *v = (char *)(&m_node->data[k_len + 1]);

    return NGX_OK;
}

ngx_int_t 
ngx_map_find_str_ngxstr(ngx_map_t *ngx_map, const char *k, ngx_str_t **v)
{
    return ngx_map_find_str_str(ngx_map, k, (char **)v);
}



ngx_int_t 
ngx_map_set_ngxstr_uintptr(ngx_map_t *ngx_map, const ngx_str_t *k, uintptr_t v)
{
    uintptr_t       hash;
    ngx_map_node_t *m_node;
    size_t          node_data_len;
    ngx_str_t      *k_str;

    node_data_len = sizeof(ngx_map_node_t) + sizeof(ngx_str_t) + k->len + 1 
        + sizeof(uintptr_t);
    m_node = map_alloc(ngx_map->pool, ngx_map->palloc, node_data_len);
    if (m_node == NULL) {
        return NGX_ERROR;
    }
    hash = ngx_crc32_long(k->data, k->len);
    m_node->node.key = hash;
    k_str = (ngx_str_t *)(&m_node->data[0]);
    k_str->data = (u_char *)(k_str + 1);
    ngx_memcpy(k_str->data, k->data, k->len);
    k_str->data[k->len] = '\0';
    k_str->len = k->len;
    *((uintptr_t *)(&m_node->data[node_data_len - sizeof(uintptr_t)])) = v;
    ngx_rbtree_insert(&ngx_map->rbtree, &m_node->node);

    return NGX_OK;
}

ngx_int_t 
ngx_map_set_ngxstr_ptr(ngx_map_t *ngx_map, const ngx_str_t *k, void *v)
{
    uintptr_t       hash;
    ngx_map_node_t *m_node;
    size_t          node_data_len;
    ngx_str_t      *k_str;

    node_data_len = sizeof(ngx_map_node_t) + sizeof(ngx_str_t) + k->len + 1 
        + sizeof(void *);
    m_node = map_alloc(ngx_map->pool, ngx_map->palloc, node_data_len);
    if (m_node == NULL) {
        return NGX_ERROR;
    }
    hash = ngx_crc32_long(k->data, k->len);
    m_node->node.key = hash;
    k_str = (ngx_str_t *)(&m_node->data[0]);
    k_str->data = (u_char *)(k_str + 1);
    ngx_memcpy(k_str->data, k->data, k->len);
    k_str->data[k->len] = '\0';
    k_str->len = k->len;
    *((void **)(&m_node->data[sizeof(ngx_str_t) + k->len + 1])) = v;
    ngx_rbtree_insert(&ngx_map->rbtree, &m_node->node);

    return NGX_OK;
}

ngx_int_t 
ngx_map_set_ngxstr_str(ngx_map_t *ngx_map, const ngx_str_t *k, const char *v)
{
    uintptr_t       hash;
    ngx_map_node_t *m_node;
    size_t          node_data_len;
    ngx_str_t      *k_str;
    size_t          v_len;

    v_len = ngx_strlen(v);
    node_data_len = sizeof(ngx_map_node_t) + sizeof(ngx_str_t) + k->len + 1 
        + v_len + 1;
    m_node = map_alloc(ngx_map->pool, ngx_map->palloc, node_data_len);
    if (m_node == NULL) {
        return NGX_ERROR;
    }
    hash = ngx_crc32_long(k->data, k->len);
    m_node->node.key = hash;
    k_str = (ngx_str_t *)(&m_node->data[0]);
    k_str->data = (u_char *)(k_str + 1);
    ngx_memcpy(k_str->data, k->data, k->len);
    k_str->data[k->len] = '\0';
    k_str->len = k->len;
    ngx_memcpy(m_node->data + k->len  + 1, (u_char *)v, v_len);
    m_node->data[k->len  + 1 + v_len] = '\0';
    ngx_rbtree_insert(&ngx_map->rbtree, &m_node->node);

    return NGX_OK;
}

ngx_int_t 
ngx_map_set_ngxstr_ngxstr(ngx_map_t *ngx_map, const ngx_str_t *k, ngx_str_t *v)
{
    uintptr_t       hash;
    ngx_map_node_t *m_node;
    size_t          node_data_len;
    ngx_str_t      *k_str;
    ngx_str_t      *v_str;

    node_data_len = sizeof(ngx_map_node_t) + 2 * sizeof(ngx_str_t) + k->len + 1 
        + v->len + 1;
    m_node = map_alloc(ngx_map->pool, ngx_map->palloc, node_data_len);
    if (m_node == NULL) {
        return NGX_ERROR;
    }
    hash = ngx_crc32_long(k->data, k->len);
    m_node->node.key = hash;
    k_str = (ngx_str_t *)(&m_node->data[0]);
    k_str->data = (u_char *)(k_str + 1);
    ngx_memcpy(k_str->data, k->data, k->len);
    k_str->data[k->len] = '\0';
    k_str->len = k->len;
    v_str = (ngx_str_t *)(&m_node->data[sizeof(ngx_str_t) + k->len + 1]);
    v_str->data = (u_char *)(v_str + 1);
    ngx_memcpy(v_str->data, v->data, v->len);
    v_str->data[v->len] = '\0';
    v_str->len = v->len;

    ngx_rbtree_insert(&ngx_map->rbtree, &m_node->node);

    return NGX_OK;
}

ngx_int_t 
ngx_map_find_ngxstr_uintptr(ngx_map_t *ngx_map, const ngx_str_t *k, uintptr_t *v)
{
    ngx_map_node_t *m_node;

    m_node = ngx_map_find_ngxstr(ngx_map, k);
    if (m_node == NULL) {
        return NGX_ERROR;
    }
    *v = *((uintptr_t *)(m_node->data + k->len + 1));

    return NGX_OK;
}

ngx_int_t 
ngx_map_find_ngxstr_ptr(ngx_map_t *ngx_map, const ngx_str_t *k, void **v)
{
    ngx_map_node_t *m_node;

    m_node = ngx_map_find_ngxstr(ngx_map, k);
    if (m_node == NULL) {
        return NGX_ERROR;
    }
    *v = *((void **)&m_node->data[sizeof(ngx_str_t) + k->len + 1]);

    return NGX_OK;
}

ngx_int_t 
ngx_map_find_ngxstr_str(ngx_map_t *ngx_map, const ngx_str_t *k, char **v)
{
    ngx_map_node_t *m_node;

    m_node = ngx_map_find_ngxstr(ngx_map, k);
    if (m_node == NULL) {
        return NGX_ERROR;
    }
    *v = (char *)(&m_node->data[sizeof(ngx_str_t) + k->len + 1]);

    return NGX_OK;
}

ngx_int_t 
ngx_map_find_ngxstr_ngxstr(ngx_map_t *ngx_map, const ngx_str_t *k, ngx_str_t **v)
{
    return ngx_map_find_ngxstr_str(ngx_map, k, (char **)v);
}



static void *
map_alloc(void *pool, ngx_palloc_pt alloc, size_t size)
{
    void *ptr;

    if (pool != NULL && alloc != NULL)
        ptr = (alloc)(pool, size);
    else
        ptr = malloc(size);

    if (ptr)
        ngx_memset(ptr, 0, size);

    return ptr;
}

static void 
map_free(void *pool, ngx_pfree_pt pfree, void *ptr)
{
    if (pool != NULL && pfree != NULL)
        (*pfree)(pool, ptr);
    else
        free(ptr);
}

static void
ngx_rbtree_set_key_ngxstr(ngx_rbtree_node_t *root, ngx_rbtree_node_t *node, 
    ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t        *temp;
    ngx_rbtree_node_t       **p;
    ngx_map_node_t           *m_node, *m_node_temp;
    ngx_str_t                *k, *k_temp;

    temp = root;
    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            m_node = (ngx_map_node_t *) node;
            m_node_temp = (ngx_map_node_t *) temp;
            k = (ngx_str_t *)(&m_node->data[0]);
            k_temp = (ngx_str_t *)(&m_node_temp->data[0]);

            p = (ngx_strcmp(k->data, k_temp->data) < 0)
                    ? &temp->left : &temp->right;
        }

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}

static void
ngx_rbtree_set_key_str(ngx_rbtree_node_t *root, ngx_rbtree_node_t *node, 
    ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t        *temp;
    ngx_rbtree_node_t       **p;
    ngx_map_node_t           *m_node, *m_node_temp;

    temp = root;
    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            m_node = (ngx_map_node_t *) node;
            m_node_temp = (ngx_map_node_t *) temp;

            p = (ngx_strcmp(m_node->data, m_node_temp->data) < 0)
                    ? &temp->left : &temp->right;
        }

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}


static void
ngx_rbtree_set_key_ptr(ngx_rbtree_node_t *root, ngx_rbtree_node_t *node,
    ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t        *temp;
    ngx_rbtree_node_t       **p;
    ngx_map_node_t           *m_node, *m_node_temp;

    temp = root;
    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            m_node = (ngx_map_node_t *) node;
            m_node_temp = (ngx_map_node_t *) temp;
            p = (*((int64_t *)&m_node->data[0]) 
                   - *((int64_t *)&m_node_temp->data[0]) < 0)
              ? &temp->left : &temp->right;
        }

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}

static ngx_map_node_t *
ngx_map_find_uintptr(ngx_map_t *ngx_map, uintptr_t k)
{
    ngx_rbtree_node_t  *node, *sentinel;

    node = ngx_map->rbtree.root;
    sentinel = ngx_map->rbtree.sentinel;

    while (node != sentinel) {

        if (k < node->key) {
            node = node->left;
            continue;
        }

        if (k > node->key) {
            node = node->right;
            continue;
        }

        /* addr == node->key */

        return (ngx_map_node_t *) node;
    }

    /* not found */

    return NULL;
}

static ngx_map_node_t *
ngx_map_find_ptr(ngx_map_t *ngx_map, void *k)
{
    uintptr_t                hash;
    int64_t                  rc;
    ngx_rbtree_node_t       *node, *sentinel;
    ngx_map_node_t          *m_node;

    hash = ngx_crc32_long(k, sizeof(void *));
    node = ngx_map->rbtree.root;
    sentinel = ngx_map->rbtree.sentinel;

    while (node != sentinel) {

        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        /* hash == node->key */
        m_node = (ngx_map_node_t *) node;
        rc = (int64_t) k - *((int64_t *) &m_node->data[0]);
        if (rc == 0) {
            return m_node;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    return NULL;
}

static ngx_map_node_t *
ngx_map_find_str(ngx_map_t *ngx_map, const char *k, size_t k_len)
{
    uintptr_t                hash;
    ngx_int_t                rc;
    ngx_rbtree_node_t       *node, *sentinel;
    ngx_map_node_t          *m_node;

    hash = ngx_crc32_long((u_char *)k, k_len);
    node = ngx_map->rbtree.root;
    sentinel = ngx_map->rbtree.sentinel;

    while (node != sentinel) {

        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        /* hash == node->key */

        m_node = (ngx_map_node_t *) node;

        rc = ngx_strncmp(k, m_node->data, k_len);

        if (rc == 0) {
            return m_node;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    return NULL;
}

static ngx_map_node_t *
ngx_map_find_ngxstr(ngx_map_t *ngx_map, const ngx_str_t *k)
{
    uintptr_t                hash;
    ngx_int_t                rc;
    ngx_rbtree_node_t       *node, *sentinel;
    ngx_map_node_t          *m_node;
    ngx_str_t               *m_node_k;

    hash = ngx_crc32_long(k->data, k->len);
    node = ngx_map->rbtree.root;
    sentinel = ngx_map->rbtree.sentinel;

    while (node != sentinel) {

        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        /* hash == node->key */

        m_node = (ngx_map_node_t *) node;
        m_node_k = (ngx_str_t *)(&m_node->data[0]);

        rc = ngx_strncmp(k->data, m_node_k->data, k->len);

        if (rc == 0) {
            return m_node;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    return NULL;
}

#if 1
void
ngx_map_test(void)
{
}
#else
void
ngx_map_test(void)
{
    {
        {
            ngx_map_t *n_map;
            int ik, iv;
            uintptr_t fv;

            n_map = ngx_map_create(NGX_MAP_UINTPTR_T, NGX_MAP_UINTPTR_T, 
                NULL, NULL, NULL);
            ik = 2;
            iv = 3;
            assert(NGX_OK == ngx_map_set_uintptr_uintptr(n_map, ik, iv));
            ik = 3;
            iv = 5;
            assert(NGX_OK == ngx_map_set_uintptr_uintptr(n_map, ik, iv));

            ik = 2;
            assert(NGX_OK == ngx_map_find_uintptr_uintptr(n_map, ik, &fv));
            assert(3 == fv);
            ik = 3;
            assert(NGX_OK == ngx_map_find_uintptr_uintptr(n_map, ik, &fv));
            assert(5 == fv);
            ngx_map_destroy(n_map);
        }

        {
            ngx_map_t *n_map;
            int ik;
            int iv, *piv, iv2, *piv2;

            piv = &iv;
            piv2 = &iv2;
            n_map = ngx_map_create(NGX_MAP_UINTPTR_T, NGX_MAP_PTR_T, 
                NULL, NULL, NULL);
            ik = 2;
            iv = 3;
            assert(NGX_OK == ngx_map_set_uintptr_ptr(n_map, ik, piv));
            ik = 3;
            iv2 = 5;
            assert(NGX_OK == ngx_map_set_uintptr_ptr(n_map, ik, piv2));

            ik = 2;
            assert(NGX_OK == ngx_map_find_uintptr_ptr(n_map, ik, (void **)&piv));
            assert(3 == *piv);
            ik = 3;
            assert(NGX_OK == ngx_map_find_uintptr_ptr(n_map, ik, (void **)&piv));
            assert(5 == *piv);
            ngx_map_destroy(n_map);
        }

        {
            ngx_map_t *n_map;
            int  ik;
            char *iv;

            n_map = ngx_map_create(NGX_MAP_UINTPTR_T, NGX_MAP_STR_T, 
                NULL, NULL, NULL);
            ik = 2;
            iv = "3";
            assert(NGX_OK == ngx_map_set_uintptr_str(n_map, ik, iv));
            ik = 3;
            iv = "55";
            assert(NGX_OK == ngx_map_set_uintptr_str(n_map, ik, iv));

            ik = 2;
            assert(NGX_OK == ngx_map_find_uintptr_str(n_map, ik, &iv));
            assert(ngx_strncmp("3", iv, ngx_strlen("3")) == 0);
            ik = 3;
            assert(NGX_OK == ngx_map_find_uintptr_str(n_map, ik, &iv));
            assert(ngx_strncmp("55", iv, ngx_strlen("55")) == 0);
            ngx_map_destroy(n_map);
        }

    }

    {
        {
            ngx_map_t *n_map;
            int ik, *pik, ik2, *pik2;
            int iv;
            uintptr_t fv;

            pik = &ik;
            pik2 = &ik2;
            n_map = ngx_map_create(NGX_MAP_PTR_T, NGX_MAP_UINTPTR_T, 
                NULL, NULL, NULL);
            iv = 3;
            assert(NGX_OK == ngx_map_set_ptr_uintptr(n_map, pik, iv));
            iv = 5;
            assert(NGX_OK == ngx_map_set_ptr_uintptr(n_map, pik2, iv));

            assert(NGX_OK == ngx_map_find_ptr_uintptr(n_map, pik, &fv));
            assert(3 == fv);
            assert(NGX_OK == ngx_map_find_ptr_uintptr(n_map, pik2, &fv));
            assert(5 == fv);
            ngx_map_destroy(n_map);
        }

        {
            ngx_map_t *n_map;
            int ik, *pik, ik2, *pik2;
            int iv, *piv, iv2, *piv2;

            pik = &ik;
            pik2 = &ik2;
            piv = &iv;
            piv2 = &iv2;
            n_map = ngx_map_create(NGX_MAP_PTR_T, NGX_MAP_PTR_T, 
                NULL, NULL, NULL);
            iv = 3;
            assert(NGX_OK == ngx_map_set_ptr_ptr(n_map, pik, piv));
            iv2 = 5;
            assert(NGX_OK == ngx_map_set_ptr_ptr(n_map, pik2, piv2));

            assert(NGX_OK == ngx_map_find_ptr_ptr(n_map, pik, (void **)&piv));
            assert(3 == *piv);
            assert(NGX_OK == ngx_map_find_ptr_ptr(n_map, pik2, (void **)&piv));
            assert(5 == *piv);
            ngx_map_destroy(n_map);
        }

        {
            ngx_map_t *n_map;
            int ik, *pik, ik2, *pik2;
            char *iv;

            pik = &ik;
            pik2 = &ik2;
            n_map = ngx_map_create(NGX_MAP_PTR_T, NGX_MAP_STR_T, 
                NULL, NULL, NULL);
            iv = "3";
            assert(NGX_OK == ngx_map_set_ptr_str(n_map, pik, iv));
            iv = "55";
            assert(NGX_OK == ngx_map_set_ptr_str(n_map, pik2, iv));

            assert(NGX_OK == ngx_map_find_ptr_str(n_map, pik, &iv));
            assert(ngx_strncmp("3", iv, ngx_strlen("3")) == 0);
            assert(NGX_OK == ngx_map_find_ptr_str(n_map, pik2, &iv));
            assert(ngx_strncmp("55", iv, ngx_strlen("55")) == 0);
            ngx_map_destroy(n_map);
        }

    }
}
#endif

