
#ifndef _NGX_MAP_H_INCLUDED_
#define _NGX_MAP_H_INCLUDED_

#include <ngx_core.h>

/* uintptr_t is the real ngx_rbtree_key_t type */

#define NGX_MAP_TYPE_MIN 1
#define NGX_MAP_TYPE_MAX 4
#define NGX_MAP_UINTPTR_T   NGX_MAP_TYPE_MIN
#define NGX_MAP_PTR_T      2
#define NGX_MAP_STR_T      3
#define NGX_MAP_NGXSTR_T  NGX_MAP_TYPE_MAX

typedef struct ngx_map_s ngx_map_t;
typedef void *(*ngx_palloc_pt)(void *pool, size_t size);
typedef ngx_int_t (*ngx_pfree_pt)(void *pool, void *p);

ngx_map_t *ngx_map_create(u_char key_type, u_char val_type, void *pool, 
    ngx_palloc_pt palloc, ngx_pfree_pt pfree);
void ngx_map_destroy(ngx_map_t *ngx_map);

ngx_int_t ngx_map_set_uintptr_uintptr(ngx_map_t *ngx_map, uintptr_t k, uintptr_t v);
ngx_int_t ngx_map_set_uintptr_ptr(ngx_map_t *ngx_map, uintptr_t k, void *v);
ngx_int_t ngx_map_set_uintptr_str(ngx_map_t *ngx_map, uintptr_t k, const char *v);
ngx_int_t ngx_map_set_uintptr_ngxstr(ngx_map_t *ngx_map, uintptr_t k, ngx_str_t *v);
ngx_int_t ngx_map_find_uintptr_uintptr(ngx_map_t *ngx_map, uintptr_t k, uintptr_t *v);
ngx_int_t ngx_map_find_uintptr_ptr(ngx_map_t *ngx_map, uintptr_t k, void **v);
ngx_int_t ngx_map_find_uintptr_str(ngx_map_t *ngx_map, uintptr_t k, char **v);
ngx_int_t ngx_map_find_uintptr_ngxstr(ngx_map_t *ngx_map, uintptr_t k, ngx_str_t **v);

ngx_int_t ngx_map_set_ptr_uintptr(ngx_map_t *ngx_map, void *k, uintptr_t v);
ngx_int_t ngx_map_set_ptr_ptr(ngx_map_t *ngx_map, void *k, void *v);
ngx_int_t ngx_map_set_ptr_str(ngx_map_t *ngx_map, void *k, const char *v);
ngx_int_t ngx_map_set_ptr_ngxstr(ngx_map_t *ngx_map, void *k, ngx_str_t *v);
ngx_int_t ngx_map_find_ptr_uintptr(ngx_map_t *ngx_map, void *k, uintptr_t *v);
ngx_int_t ngx_map_find_ptr_ptr(ngx_map_t *ngx_map, void *k, void **v);
ngx_int_t ngx_map_find_ptr_str(ngx_map_t *ngx_map, void *k, char **v);
ngx_int_t ngx_map_find_ptr_ngxstr(ngx_map_t *ngx_map, void *k, ngx_str_t **v);

ngx_int_t ngx_map_set_str_uintptr(ngx_map_t *ngx_map, const char *k, uintptr_t v);
ngx_int_t ngx_map_set_str_ptr(ngx_map_t *ngx_map, const char *k, void *v);
ngx_int_t ngx_map_set_str_str(ngx_map_t *ngx_map, const char *k, const char *v);
ngx_int_t ngx_map_set_str_ngxstr(ngx_map_t *ngx_map, const char *k, ngx_str_t *v);
ngx_int_t ngx_map_find_str_uintptr(ngx_map_t *ngx_map, const char *k, uintptr_t *v);
ngx_int_t ngx_map_find_str_ptr(ngx_map_t *ngx_map, const char *k, void **v);
ngx_int_t ngx_map_find_str_str(ngx_map_t *ngx_map, const char *k, char **v);
ngx_int_t ngx_map_find_str_ngxstr(ngx_map_t *ngx_map, const char *k, ngx_str_t **v);

ngx_int_t ngx_map_set_ngxstr_uintptr(ngx_map_t *ngx_map, const ngx_str_t *k, 
    uintptr_t v);
ngx_int_t ngx_map_set_ngxstr_ptr(ngx_map_t *ngx_map, const ngx_str_t *k, 
    void *v);
ngx_int_t ngx_map_set_ngxstr_str(ngx_map_t *ngx_map, const ngx_str_t *k, 
    const char *v);
ngx_int_t ngx_map_set_ngxstr_ngxstr(ngx_map_t *ngx_map, const ngx_str_t *k, 
    ngx_str_t *v);
ngx_int_t ngx_map_find_ngxstr_uintptr(ngx_map_t *ngx_map, const ngx_str_t *k, 
    uintptr_t *v);
ngx_int_t ngx_map_find_ngxstr_ptr(ngx_map_t *ngx_map, const ngx_str_t *k, 
    void **v);
ngx_int_t ngx_map_find_ngxstr_str(ngx_map_t *ngx_map, const ngx_str_t *k, 
    char **v);
ngx_int_t ngx_map_find_ngxstr_ngxstr(ngx_map_t *ngx_map, const ngx_str_t *k, 
    ngx_str_t **v);

void ngx_map_test(void);


#endif

