#ifndef CS241_DISPATCH_H
#define CS241_DISPATCH_H

#include <pthread.h>
#include <pcap.h>
#include "queue.h"
#include "sniff.h"

#define POOL_SIZE 4

typedef struct dispatch
{
    queue q;
    pthread_mutex_t m_lock;
    pthread_cond_t cond;
    pthread_t threads[POOL_SIZE];
} dispatch;

void dispatch_packet(dispatch* d, packet p);
dispatch* dispatch_init(int verbose);
void dispatch_destroy(dispatch* d);

#endif
