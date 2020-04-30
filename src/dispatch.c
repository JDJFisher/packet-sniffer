#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>

#include "dispatch.h"
#include "analysis.h"
#include "queue.h"
#include "sniff.h"

static volatile sig_atomic_t stop;

void dispatch_packet(dispatch* d, packet p)
{
    // Lock access to the packet queue
    pthread_mutex_lock(&d->m_lock);

    // Add packet to task queue
    enqueue(&d->q, p);

    pthread_mutex_unlock(&d->m_lock);

    // Wake a waiting thread to handle the new task
    pthread_cond_signal(&d->cond);
}

void *worker_routine(void* arg)
{
    dispatch* d = (dispatch*) arg;

    while(1)
    {
        // Lock access to the packet queue
        pthread_mutex_lock(&d->m_lock);

        while (queue_empty(&d->q) && !stop)
        {   // Have the thread sleep until the queue contains a packet to work on
            pthread_cond_wait(&d->cond, &d->m_lock);
        }

        // Exit from work cycle
        if(stop) break;

        // Retrieve a packet from the task queue
        packet task;
        dequeue(&d->q, &task);

        // Unlock the critical region
        pthread_mutex_unlock(&d->m_lock);

        // Analyse the packet retrieved from the queue
        analyse(task);
    }

    // Ensure the lock has been released before joining
    pthread_mutex_unlock(&d->m_lock);
    pthread_exit(NULL);
    return NULL;
}

dispatch* dispatch_init(int verbose)
{
    // Allocate space for the dispatch struct
    dispatch* d = (dispatch*)malloc(sizeof(dispatch));
    if(d == NULL) return NULL;

    // Initialise task queue
    queue_init(&d->q);

    // Initialise queue semaphore variables
    pthread_mutex_init(&d->m_lock, NULL);
    pthread_cond_init(&d->cond, NULL);

    // Create threads
    unsigned int i;
    stop = 0;
    for(i = 0; i < POOL_SIZE; i++)
    {
        if (pthread_create(&d->threads[i], NULL, &worker_routine, (void *) d) < 0) return NULL;
    }

    if (verbose) printf("Thread pool initialised\n");
    return d;
}

void dispatch_destroy(dispatch* d)
{
    // Break the thread workers from their work cycle
    stop = 1;

    // Wake any sleeping threads waiting for packets
    pthread_cond_broadcast(&d->cond);

    // Wait for all the threads to join
    unsigned int i;
    for(i = 0; i < POOL_SIZE; i++)
    {
        if (pthread_join(d->threads[i], (void**) NULL) < 0) perror("error");
    }

    // Clear the unprocessed packets from the queue
    queue_clear(&d->q);

    // Destroy the queue semaphore variables
    pthread_mutex_destroy(&d->m_lock);
    pthread_cond_destroy(&d->cond);

    free(d);
}
