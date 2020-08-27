#ifndef PROD_CON_QUEUE_H
#define PROD_CON_QUEUE_H

#include <queue>
#include <mutex>
#include <condition_variable>
#include <stdint.h>
#include <string>

struct prod_con_queue {
    std::queue<std::string> queue;
    int max_size;
    std::mutex mutex;
    std::condition_variable condition;
    
    prod_con_queue(int max_size);
    void add(std::string item);
    std::string consume();
    bool is_full() const;
    bool is_empty() const;
    int length() const;
};

#endif

