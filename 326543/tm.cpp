/**
 * @file   tm.cpp
 * @author [...]
 *
 * @section LICENSE
 *
 * [...]
 *
 * @section DESCRIPTION
 *
 * Implementation of your own transaction manager.
 * You can completely rewrite this file (and create more files) as you wish.
 * Only the interface (i.e. exported symbols and semantic) must be preserved.
**/

// Requested features
#define _GNU_SOURCE
#define _POSIX_C_SOURCE   200809L
#ifdef __STDC_NO_ATOMICS__
    #error Current C11 compiler does not support atomic operations
#endif

// External headers
#include <string.h>
#include <vector>
#include <mutex>

// Internal headers
#include <tm.hpp>

using namespace std;

// -------------------------------------------------------------------------- //

/** Define a proposition as likely true.
 * @param prop Proposition
**/
#undef likely
#ifdef __GNUC__
    #define likely(prop) \
        __builtin_expect((prop) ? 1 : 0, 1)
#else
    #define likely(prop) \
        (prop)
#endif

/** Define a proposition as likely false.
 * @param prop Proposition
**/
#undef unlikely
#ifdef __GNUC__
    #define unlikely(prop) \
        __builtin_expect((prop) ? 1 : 0, 0)
#else
    #define unlikely(prop) \
        (prop)
#endif

/** Define one or several attributes.
 * @param type... Attribute names
**/
#undef as
#ifdef __GNUC__
    #define as(type...) \
        __attribute__((type))
#else
    #define as(type...)
    #warning This compiler has no support for GCC attributes
#endif

// -------------------------------------------------------------------------- //

static const tx_t read_only_tx  = UINTPTR_MAX - 10;
static const tx_t read_write_tx = UINTPTR_MAX - 11;

// --------------- Structures ----------------------------------------------- //

typedef struct region region_t;
typedef struct segment segment_t;
typedef struct transaction transaction_t;
typedef struct write_log write_log_t;

// Represents a shared memory region
struct region {
    void* start;        // Start of the shared memory region
    vector<segment_t*> segments; // Segments belonging to the region
    size_t size;        // Size of the shared memory region (in bytes)
    size_t align;       // Claimed alignment of the shared memory region (in bytes)
};

// Represents a memory segment
struct segment {
    void* start; // Start of segment
    size_t size; // Size of segment
    shared_mutex* lock; // Segment-wise lock
};

// Represents a transaction
struct transaction {
    bool is_ro; // Whether transaction is read_only
    vector<shared_mutex*> read_locks; 
    vector<shared_mutex*> write_locks;
    vector<write_log*> write_logs; // Keep track of old values for writes for rolling back  
    vector<shared_mutex*> alloc_locks;
    vector<segment_t*> alloc_segments;
    vector<shared_mutex*> free_locks;
    vector<segment_t*> free_segments;
};

// Represents a write log entry
struct write_log {
    void* address;
    void* old_data;
    size_t size;
};

// --------------- Helper functions ----------------------------------------- //

// Find target segment for read/write/free
segment_t* find_seg(region_t* region, transaction_t* tx, const void* addr) {
    // Search in shared memory (includes allocated segments by any transactions)
    for(auto seg : region->segments) {
        if(addr >= seg->start && addr < (char*)seg->start + seg->size) {
            return seg;
        }
    }
    return NULL;
}

// Check if a transaction acquired a segment lock
bool have_lock(transaction_t* tx, shared_mutex* lock) {
    for (auto read_lock : tx->read_locks) {
        if (read_lock == lock) return true;
    }
    // For read-only transactions, no need to go further
    if (tx->is_ro) return false;

    for (auto read_lock : tx->write_locks) {
        if (read_lock == lock) return true;
    }

    return false;
}

// Rollback a transaction when it fails
void rollback(transaction_t* tx, region_t* region) {
    // Rollback writes
    for (auto write_log : tx->write_logs) {
        memcpy(write_log->address, write_log->old_data, write_log->size);
    }
    // Roll back allocations
    free_segments(region, tx->alloc_segments);
}

// Free segments
void free_segments(region_t* region, vector<segment*> to_free) {
    for (auto free_seg : to_free) {
        int index = 0;
        for (auto seg : region->segments) {
            if (free_seg == seg) {
                region->segments.erase(region->segments.begin() + index);
                break;
            }
            else index++;
        }        
    }
}

// Cleanup a transaction
void cleanup(transaction_t* tx) {
    tx->read_locks.clear();
    if (!tx->is_ro) {
        // Cleanup write locks and write logs
        tx->write_locks.clear();
        for (auto write_log : tx->write_logs) {
            free(write_log->address);
            free(write_log->old_data);
            delete write_log;
        }
        // Cleanup other locks
        for (auto alloc_seg : tx->alloc_segments) {
            free(alloc_seg->start);
            delete alloc_seg;
        }
        tx->alloc_locks.clear();
        for (auto free_seg : tx->free_segments) {
            free(free_seg->start);
            delete free_seg;
        }
        tx->free_locks.clear();
    }
}

// -------------------------------------------------------------------------- //


/** Create (i.e. allocate + init) a new shared memory region, with one first non-free-able allocated segment of the requested size and alignment.
 * @param size  Size of the first shared segment of memory to allocate (in bytes), must be a positive multiple of the alignment
 * @param align Alignment (in bytes, must be a power of 2) that the shared memory region must support
 * @return Opaque shared memory region handle, 'invalid_shared' on failure
**/
shared_t tm_create(size_t size, size_t align) noexcept {
    region_t* region = new region_t(); 
    if (unlikely(!region)) {
        return invalid_shared;
    }
    segment_t* first = new segment_t();
    if (unlikely(!first)) {
        delete region;
        return invalid_shared;
    }
    if (unlikely(posix_memalign(&(region->start), align, size) != 0)) {
        delete first;
        delete region;
        return invalid_shared;
    }

    memset(region->start, 0, size); // Fill first allocated segment with zeros
    // Init segment 
    first->start = region->start;
    first->size = size;

    // Init region 
    region->size = size;
    region->align = align;
    region->segments.push_back(first);

    return region;
}

/** Destroy (i.e. clean-up + free) a given shared memory region.
 * @param shared Shared memory region to destroy, with no running transaction
**/
void tm_destroy(shared_t shared) noexcept {
    region_t* region = (region_t*) shared;
    for (auto seg : region->segments) {
        free(seg->start);
        delete seg;
    }
    delete region;
  
}

/** [thread-safe] Return the start address of the first allocated segment in the shared memory region.
 * @param shared Shared memory region to query
 * @return Start address of the first allocated segment
**/
void* tm_start(shared_t shared) noexcept {
    return ((region_t*) shared)->start;
}

/** [thread-safe] Return the size (in bytes) of the first allocated segment of the shared memory region.
 * @param shared Shared memory region to query
 * @return First allocated segment size
**/
size_t tm_size(shared_t shared) noexcept {
    return ((region_t*) shared)->size;
}

/** [thread-safe] Return the alignment (in bytes) of the memory accesses on the given shared memory region.
 * @param shared Shared memory region to query
 * @return Alignment used globally
**/
size_t tm_align(shared_t shared) noexcept {
    return ((region_t*) shared)->align;
}

/** [thread-safe] Begin a new transaction on the given shared memory region.
 * @param shared Shared memory region to start a transaction on
 * @param is_ro  Whether the transaction is read-only
 * @return Opaque transaction ID, 'invalid_tx' on failure
**/
tx_t tm_begin(shared_t shared, bool is_ro) noexcept {
    transaction_t* tx = new transaction_t();
    if (unlikely(!tx)) {
        return invalid_tx;
    }
    tx->is_ro = is_ro;
    return (tx_t) tx;
}

/** [thread-safe] End the given transaction.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to end
 * @return Whether the whole transaction committed
**/
bool tm_end(shared_t shared, tx_t tx) noexcept {
    region_t* region = (region_t*) shared;
    transaction_t* transaction = new transaction_t();
    // Release read locks
    for (auto lock : transaction->read_locks) {
        lock->unlock();
    }
    if (!transaction->is_ro) {
        // Free
        free_segments(region, transaction->free_segments);
        // Release write locks
        for (auto lock : transaction->write_locks) {
            lock->unlock();
        }
        transaction->write_locks.clear();   
        // Release alloc locks 
        for (auto lock : transaction->alloc_locks) {
            lock->unlock();
        }
        // Release free locks 
        for (auto lock : transaction->free_locks) {
            lock->unlock();
        }

    }
    cleanup(transaction);
    return true;
     
}

/** [thread-safe] Read operation in the given transaction, source in the shared region and target in a private region.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to use
 * @param source Source start address (in the shared region)
 * @param size   Length to copy (in bytes), must be a positive multiple of the alignment
 * @param target Target start address (in a private region)
 * @return Whether the whole transaction can continue
**/
bool tm_read(shared_t shared, tx_t tx, void const* source, size_t size, void* target) noexcept{
    region_t* region = (region_t*) shared;
    transaction_t* transaction = (transaction_t*) tx;
    segment_t* seg = find_seg(region, transaction, source);
    // Rollback if trying to read memory that doesn't exist
    if (unlikely(!seg)) {
        rollback(transaction, region);
        cleanup(transaction);
        return false;
    }
    // If I acquired the lock, do the read
    if (have_lock(transaction, seg->lock)) {
        memcpy(target, source, size);
        return true;
    }
    // Try to acquire
    // Store read lock and perform the read if successful, otherwise rollback and abort 
    else {
        if (seg->lock->try_lock()) {
            transaction->read_locks.push_back(seg->lock);
            memcpy(target, source, size);
            return true;
        }
        else {
            rollback(transaction, region);
            cleanup(transaction);
            return false;
        }
    } 
}

/** [thread-safe] Write operation in the given transaction, source in a private region and target in the shared region.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to use
 * @param source Source start address (in a private region)
 * @param size   Length to copy (in bytes), must be a positive multiple of the alignment
 * @param target Target start address (in the shared region)
 * @return Whether the whole transaction can continue
**/
bool tm_write(shared_t shared, tx_t tx, void const* source, size_t size, void* target) noexcept {
    region_t* region = (region_t*) shared;
    transaction_t* transaction = (transaction_t*) tx;
    segment_t* seg = find_seg(region, transaction, target);
    // Fail and rollback if trying to write into memory that doesn't exist
    if (unlikely(!seg)) {
        rollback(transaction, region);
        cleanup(transaction);
        return false;
    }
    // If I acquired the lock, log and perform the write
    if (have_lock(transaction, seg->lock)) {
        write_log_t* write_log = new write_log_t();
        write_log->address = target;
        write_log->old_data = malloc(size);
        memcpy(write_log->old_data, source, size);
        write_log->size = size;    
        memcpy(target, source, size);
        return true;
    }
    // Try to acquire
    // Store write lock and log and perform the write if successful, otherwise rollback and abort
    else {
        if (seg->lock->try_lock()) {
            transaction->write_locks.push_back(seg->lock);
            write_log_t* write_log = new write_log_t();
            write_log->address = target;
            write_log->old_data = malloc(size);
            memcpy(write_log->old_data, source, size);
            write_log->size = size;    
            memcpy(target, source, size);
            return true;
        }
        else {
            rollback(transaction, region);
            cleanup(transaction);
            return false;
        }    
    }
    return true;
}

/** [thread-safe] Memory allocation in the given transaction.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to use
 * @param size   Allocation requested size (in bytes), must be a positive multiple of the alignment
 * @param target Pointer in private memory receiving the address of the first byte of the newly allocated, aligned segment
 * @return Whether the whole transaction can continue (success/nomem), or not (abort_alloc)
**/
Alloc tm_alloc(shared_t shared, tx_t tx, size_t size, void** target) noexcept {
    region_t* region = (region_t*) shared;
    transaction_t* transaction = (transaction_t*) tx;
    segment_t* new_segment = new segment_t();
    if (unlikely(!new_segment)) {
        return Alloc::nomem;
    }
    if (unlikely(posix_memalign(&(new_segment->start), region->align, size) != 0)) {
        delete new_segment;
        return Alloc::nomem;
    }
    // Initialise new segment, lock it (to prevent other transactions from allocating overlapping segments)
    memset(new_segment->start, 0, size);
    new_segment->size = size;
    new_segment->lock->lock();
    transaction->alloc_segments.push_back(new_segment);
    transaction->alloc_locks.push_back(new_segment->lock);
    *target = new_segment->start;
    region->segments.push_back(new_segment);
    return Alloc::success;
}

/** [thread-safe] Memory freeing in the given transaction.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to use
 * @param target Address of the first byte of the previously allocated segment to deallocate
 * @return Whether the whole transaction can continue
**/
bool tm_free(shared_t shared, tx_t tx, void* target) noexcept {
    region_t* region = (region_t*) shared;
    transaction_t* transaction = (transaction_t*) tx;
    segment_t* free_segment = find_seg(region, transaction, target);
    // Trying to free nonexistent memory, rollback and abort
    if (unlikely(!free_segment)) {
        rollback(transaction, region);
        cleanup(transaction);
        return false;
    }
    // If I acquired the lock, add free lock and remember that we have to free 
    if (have_lock(transaction, free_segment->lock)) {
        transaction->free_locks.push_back(free_segment->lock);
        transaction->free_segments.push_back(free_segment->lock);
    }
    // Try to acquire
    // Add free lock and remember that we have to free if successful, otherwise rollback and abort
    else {
        if (free_segment->lock->try_lock()) {
            transaction->free_locks.push_back(free_segment->lock);
            transaction->free_segments.push_back(free_segment->lock);
        }
        else {
            rollback(transaction, region);
            cleanup(transaction);
            return false;
        }
    }
    
    return true;

}
