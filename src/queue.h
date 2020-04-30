#ifndef CS241_QUEUE_H
#define CS241_QUEUE_H

#include "sniff.h"

typedef struct queue
{
    struct element* head;
    struct element* tail;
    unsigned int size;
} queue;

void queue_init(queue* q);
int enqueue(queue* q, packet value);
int dequeue(queue* q, packet* ret_val);
void queue_clear(queue* q);
int queue_size(queue* q);
int queue_empty(queue* q);

#endif
