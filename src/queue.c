#include <stdlib.h>
#include <stdio.h>

#include "queue.h"
#include "sniff.h"

typedef struct element
{
    struct element* next;
    packet value;
} element;

void queue_init(queue* q)
{
    q->head = q->tail = NULL;
    q->size = 0;
}

int enqueue(queue* q, packet value)
{
    // Allocate space for new element node to store the value
    element* new_elem = malloc(sizeof(element));
    if(new_elem == NULL)
    {
        perror("Failed to enqueue value");
        return -1;
    }

    // Store the value in the new element
    new_elem->next = NULL;
    new_elem->value = value;

    if (q->size == 0)
    {   // The queue is empty
        q->head = q->tail = new_elem;
    }
    else
    {   // The queue has at least one element
        q->tail->next = new_elem;
        q->tail = new_elem;
    }

    q->size++;
    return 0;
}

int dequeue(queue* q, packet* ret_val)
{
    // Check if the queue is empty
    if (q->size == 0) return -1;

    // Retrieve head value
    element* old_head = q->head;
    *ret_val = old_head->value;

    // Update the head of the queue
    q->head = old_head->next;

    // Release the old head element node structure
    free(old_head);
    old_head = NULL;

    q->size--;
    return 0;
}

void queue_clear(queue* q)
{
    // Dequeue items until the queue is empty
    while(!queue_empty(q))
    {
        packet temp;
        dequeue(q, &temp);
    }
}

int queue_size(queue* q)
{
    return q->size;
}

int queue_empty(queue* q)
{
    return q->size == 0;
}
