package com.packetanalyzer.dpi;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Bounded, blocking, thread-safe queue used to pass packets between the
 * reader, load-balancer, and fast-path threads.
 * <p>{@code ThreadSafeQueue<T>} template defined
 * {@code DPI::ThreadSafeQueue} in thread_safe_queue.
 * @param <T> element type
 */
public final class ThreadSafeQueue<T> {

    private final Deque<T> queue = new ArrayDeque<>();
    private final ReentrantLock lock = new ReentrantLock();
    private final Condition notEmpty = lock.newCondition();
    private final Condition notFull = lock.newCondition();
    private final int maxSize;
    private volatile boolean shutdown = false;

    public ThreadSafeQueue(int maxSize) {
        this.maxSize = maxSize;
    }

    /** Blocks while the queue is full; the item is silently dropped if the queue has been shut down. */
    public void push(T item) {
        lock.lock();
        try {
            while (queue.size() >= maxSize && !shutdown) {
                notFull.awaitUninterruptibly();
            }
            if (shutdown) {
                return;
            }
            queue.addLast(item);
            notEmpty.signal();
        } finally {
            lock.unlock();
        }
    }

    /** Waits up to {@code timeoutMs} for an item; empty on timeout, empty queue, or shutdown. */
    public Optional<T> pop(long timeoutMs) {
        lock.lock();
        try {
            long nanos = TimeUnit.MILLISECONDS.toNanos(timeoutMs);
            while (queue.isEmpty() && !shutdown) {
                if (nanos <= 0L) {
                    return Optional.empty();
                }
                nanos = notEmpty.awaitNanos(nanos);
            }
            if (queue.isEmpty()) {
                return Optional.empty();
            }
            T item = queue.removeFirst();
            notFull.signal();
            return Optional.of(item);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return Optional.empty();
        } finally {
            lock.unlock();
        }
    }

    public void shutdown() {
        lock.lock();
        try {
            shutdown = true;
            notEmpty.signalAll();
            notFull.signalAll();
        } finally {
            lock.unlock();
        }
    }

    public int size() {
        lock.lock();
        try {
            return queue.size();
        } finally {
            lock.unlock();
        }
    }

    public boolean isShutdown() {
        return shutdown;
    }
}
