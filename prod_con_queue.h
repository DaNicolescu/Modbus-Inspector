#ifndef PROD_CON_QUEUE_H
#define PROD_CON_QUEUE_H

#include <queue>
#include <mutex>
#include <condition_variable>
#include <stdint.h>

struct msg_buf {
    uint8_t *payload;
    uint16_t length;
};

struct prod_con_queue {
    std::queue<struct msg_buf*> queue;
    int max_size;
    std::mutex mutex;
    std::condition_variable condition;
    
    prod_con_queue(int max_size);
    void add(struct msg_buf *item);
    struct msg_buf *consume();
    bool is_full() const;
    bool is_empty() const;
    int length() const;
};

#endif

