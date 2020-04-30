#include <stdlib.h>
#include <stdio.h>

#include "arrayset.h"

#define INITIAL_CAPACITY 16

int arrayset_init(arrayset* al)
{
    al->capacity = INITIAL_CAPACITY;
    al->size = 0;

    // Allocate space for the first INITIAL_CAPACITY elements of the set
    al->addresses = malloc(INITIAL_CAPACITY * sizeof(u_int32_t));
    if(al->addresses == NULL)
    {
        perror("Failed to initialise arrayset");
        return -1;
    }

    return 0;
}

int arrayset_add(arrayset* al, u_int32_t addr)
{
    if (contains(al, addr))
    {   // The element is already a member of the set, don't add it again
        return 0;
    }
    else if (al->size == al->capacity)
    {   // The array is full reallocate memory for it and double its capacity
        u_int32_t* temp = realloc(al->addresses, 2 * al->capacity * sizeof(u_int32_t));
        if(temp == NULL) return -1;

        al->addresses = temp;
        al->capacity *= 2;
    }

    // Add the element to the next available slot in the array
    al->addresses[al->size] = addr;
    al->size++;
    return 0;
}

int contains(arrayset* al, u_int32_t addr)
{
    size_t i;
    for (i = 0; i < al->size; i++)
    {   // Iterate over all elements stored in the array looking for a match
        if(al->addresses[i] == addr) return 1;
    }

    return 0;
}

size_t arrayset_size(arrayset* al)
{
    return al->size;
}

int arrayset_empty(arrayset* al)
{
    return al->size == 0;
}

void arrayset_clear(arrayset* al)
{
    // Destroy the arrayset and create a new empty set at the same address
    arrayset_destroy(al);
    arrayset_init(al);
}

void arrayset_destroy(arrayset* al)
{
    // Free the memory allocated to the arar
    free(al->addresses);
}
