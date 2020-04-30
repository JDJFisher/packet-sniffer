#ifndef CS241_ARRAYSET_H
#define CS241_ARRAYSET_H

#include <arpa/inet.h>

typedef struct arrayset
{
    size_t capacity;
    size_t size;
    u_int32_t* addresses;
} arrayset;

int arrayset_init(arrayset* al);
int arrayset_add(arrayset* al, u_int32_t adrr);
int contains(arrayset* al, u_int32_t adrr);
size_t arrayset_size(arrayset* al);
int arrayset_empty(arrayset* al);
void arrayset_clear(arrayset* al);
void arrayset_destroy(arrayset* al);

#endif
