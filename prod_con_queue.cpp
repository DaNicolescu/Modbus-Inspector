#include "prod_con_queue.h"

prod_con_queue::prod_con_queue(int max_size)
    : max_size(max_size)
{
}

void prod_con_queue::add(std::string item)
{
    std::unique_lock<std::mutex> lock(this->mutex);
    this->condition.wait(lock, [this]()
    { return !is_full(); });
    this->queue.push(item);
    lock.unlock();
    this->condition.notify_all();
}

std::string prod_con_queue::consume()
{
    std::string item;

    std::unique_lock<std::mutex> lock(this->mutex);
    this->condition.wait(lock, [this]()
    { return !is_empty(); });
    item = this->queue.front();
    this->queue.pop();
    lock.unlock();
    this->condition.notify_all();

    return item;
}

bool prod_con_queue::is_full() const
{
    return this->queue.size() >= this->max_size;
}

bool prod_con_queue::is_empty() const
{
    return this->queue.size() == 0;
}

int prod_con_queue::length() const
{
    return this->queue.size();
}

