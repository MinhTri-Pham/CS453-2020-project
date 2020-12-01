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
#include <atomic>

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

struct segment {
    void* start;
    size_t size;
    atomic<int> lock;
};

struct transaction {
    region_t* region;
    bool is_ro;
    vector<atomic<int>*> read_locks;
    vector<atomic<int>*> write_locks;
    vector<atomic<int>*> alloc_locks;
    vector<segment_t*> alloc_segments;
    vector<atomic<int>*> free_locks;
    vector<segment_t*> free_segments;
    write_log_t* write_logs; 
};

// Linked list of write logs in case we need to roll back
struct write_log {
    void* location;
    void* old_data;
    size_t size;
    struct write_log* next;
};

// --------------- Helper functions ----------------------------------------- //

// Find target segment for read/write/free
segment_t* find_seg(region_t* region, const void* target) {
    for(auto seg : region->segments) {
        if(target >= seg->start && target < seg->start + seg->size) {
            return seg;
        }
    }
}


// Check if a transaction acquired a segment lock
bool have_lock(transaction_t* tx, atomic<int>* lock) {
    for (auto read_lock : tx->read_locks) {
        if (read_lock == lock) return true;
    }
    // For read-only transactions, just need to check read locks
    if (tx->is_ro) return false;

    for (auto write_lock : tx->write_locks) {
        if (write_lock == lock) return true;
    }

    for (auto alloc_lock : tx->alloc_locks) {
        if (alloc_lock == lock) return true;
    }

    for (auto free_lock : tx->free_locks) {
        if (free_lock == lock) return true;
    }

    return false;
}

// Free segments
void free_segs(transaction_t* trans, vector<segment*> to_free){
    int index = 0;
    for(auto seg : trans->region->segments){
        for(auto seg_to_free : to_free){
            if(seg == seg_to_free){
                trans->region->segments.erase(trans->region->segments.begin() + index);
                free(seg->start);
                delete seg;
            }
        }
        ++index;
    }
    return;
}

// Rollback a transaction when it fails
void rollback(transaction_t* tx){
    // Unlock read locks
    for (auto read_lock : tx->read_locks) {
       int expected = 1;
       atomic_compare_exchange_strong(read_lock, &expected, 0);
    }
    if (!tx->is_ro){
        // Rollback writes
        // Cleaup write logs
        write_log_t* write_log = tx->write_logs;
        write_log_t* temp;
        while(write_log != NULL){
            memcpy(write_log->location, write_log->old_data, write_log->size);
            free(write_log->old_data);
            temp = write_log->next;
            delete write_log;
            write_log = temp;
        }
        // Rollback allocations
        free_segs(tx, tx->alloc_segments);

        // Unlock all other locks
        for (auto write_lock : tx->write_locks) {
           int expected = 1;
           atomic_compare_exchange_strong(write_lock, &expected, 0);
        }
        for (auto free_lock : tx->free_locks) {
           int expected = 1;
           atomic_compare_exchange_strong(free_lock, &expected, 0);
        }
    }
    delete tx;
    return;
}

// -------------------------------------------------------------------------- //

/** Create (i.e. allocate + init) a new shared memory region, with one first non-free-able allocated segment of the requested size and alignment.
 * @param size  Size of the first shared segment of memory to allocate (in bytes), must be a positive multiple of the alignment
 * @param align Alignment (in bytes, must be a power of 2) that the shared memory region must support
 * @return Opaque shared memory region handle, 'invalid_shared' on failure
**/
shared_t tm_create(size_t size, size_t align) noexcept{
    region_t* region = new region_t();
    if (unlikely(!region)) {
        return invalid_shared;
    }
    segment_t* first = new segment_t();
    if (unlikely(!first)) {
        delete region;
        return invalid_shared;
    }
    if (unlikely(posix_memalign(&(region->start), align, size) != 0)){
        delete first;
        delete region;
        return invalid_shared;
    }
    // Init segment and region
    memset(region->start, 0, size); // Fill first allocated segment with zeros
    first->start = region->start;
    first->size = size;
    first->lock = 0;
    region->align = align;
    region->size = size;
    region->segments.push_back(first);
    return region;
}
/** Destroy (i.e. clean-up + free) a given shared memory region.
 * @param shared Shared memory region to destroy, with no running transaction
**/
void tm_destroy(shared_t shared ) noexcept {
    region_t* region = (region_t*) shared;
    for (auto seg : region->segments){
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
    if(unlikely(tx == NULL)){
       return invalid_tx;
    }
    tx->region = (region_t*) shared;
    tx->is_ro = is_ro;
    tx->write_logs = NULL;
    return (tx_t) tx;
}

/** [thread-safe] End the given transaction.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to end
 * @return Whether the whole transaction committed
**/
bool tm_end(shared_t shared, tx_t tx) noexcept {
    transaction_t* transaction = (transaction_t*) tx;
    for (auto read_lock : transaction->read_locks) {
       int expected = 1;
       atomic_compare_exchange_strong(read_lock, &expected, 0);
    }
    if (!transaction ->is_ro){
        // Free
        free_segs(transaction, transaction->free_segments);
        // Release write locks
        for (auto write_lock : transaction->write_locks) {
            int expected = 1;
            atomic_compare_exchange_strong(write_lock, &expected, 0);
        }
        // Release alloc locks 
        for (auto alloc_lock : transaction->alloc_locks) {
            int expected = 1;
            atomic_compare_exchange_strong(alloc_lock, &expected, 0);
        }
        // Release free locks 
        for (auto free_lock : transaction->free_locks) {
            int expected = 1;
            atomic_compare_exchange_strong(free_lock, &expected, 0);
        }
        // Clean up write logs
        write_log_t* write_log = transaction->write_logs;
        write_log_t* temp;
        while(write_log != NULL){
            free(write_log->old_data);
            temp = write_log->next;
            delete write_log;
            write_log = temp;
        }
    }
    delete transaction;
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
bool tm_read(shared_t shared, tx_t tx, void const* source, size_t size, void* target) noexcept {
    region_t* region = (region_t*) shared;
    transaction_t* transaction = (transaction_t*) tx;
    segment_t* seg = find_seg(region, source);
    // Rollback if trying to read memory that doesn't exist
    if (!unlikely(seg)) {
        rollback(transaction);
        return false;
    }
    // Try to acquire the segment lock unless the transaction already has it
    // Abort if this fails
    if (!have_lock(transaction, &seg->lock)){
        int expected = 0;
        if(!atomic_compare_exchange_strong(&seg->lock, &expected, 1)){
            rollback(transaction);
            return false;
        } else transaction->read_locks.push_back(&seg->lock);
    }
    // Commit read
    memcpy(target, source, size);
    return true;
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
    region_t* reg = (region_t*) shared;
    transaction_t* transaction = (transaction_t*) tx;
    segment_t* seg = find_seg(reg, target);
    // Rollback if trying to write into memory that doesn't exist
    if (unlikely(!seg)) {
        rollback(transaction);
        return false;
    }
    // Try to acquire the segment lock unless the transaction already has it
    // Abort if this fails
    if (!have_lock(transaction, &seg->lock)){
        int expected = 0;
        if(!atomic_compare_exchange_strong(&seg->lock, &expected, 1)){
            rollback(transaction);
            return false;
        } else {
            transaction->write_locks.push_back(&seg->lock);
        }
    }
    write_log_t* new_log = new write_log_t();
    if (unlikely(!new_log)){
        rollback(transaction);
        return false;
    }
    new_log->old_data = malloc(sizeof(byte) * size);
    if (unlikely(!new_log->old_data)){
        rollback(transaction);
        return false;
    }
    // Add a new entry to the write logs
    memcpy(new_log->old_data, target, size);
    new_log->size = size;
    new_log->location = target;
    new_log->next = transaction->write_logs;
    transaction->write_logs = new_log;

    // Commit the write
    memcpy(target, source, size);
    return true;

}

/** [thread-safe] Memory allocation in the given transaction.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to use
 * @param size   Allocation requested size (in bytes), must be a positive multiple of the alignment
 * @param target Pointer in private memory receiving the address of the first byte of the newly allocated, aligned segment
 * @return Whether the whole transaction can continue (success/nomem), or not (abort_alloc)
**/
Alloc tm_alloc(shared_t shared, tx_t tx as(unused), size_t size, void** target) noexcept {
    region_t* region = (region_t*) shared;
    segment_t* new_segment = new segment_t();
    if (unlikely(!new_segment)) {
        return Alloc::nomem;
    }

    if (unlikely(posix_memalign((void**) &(new_segment->start), region->align, size) != 0)){
        delete new_segment;
        return Alloc::nomem;
    }
    // Initialise new segment, lock it (to prevent other transactions from allocating overlapping segments)
    memset(new_segment->start, 0, size);
    *target = new_segment->start;
    new_segment->size = size;
    new_segment->lock = 1;
    ((transaction_t*) tx)->alloc_locks.push_back(&new_segment->lock);
    ((transaction_t*) tx)->alloc_segments.push_back(new_segment);
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
    segment_t* free_segment = find_seg(region, target);
    // Rollback if trying to free nonexistent memory
    if (unlikely(!free_segment)) {
        rollback(transaction);
        return false;
    }  
    // Try to acquire the segment lock unless the transaction already has it
    // Abort if this fails
    if(!have_lock(transaction, &free_segment->lock)){
        int expected = 0;
        if (!atomic_compare_exchange_strong(&free_segment->lock, &expected, 1)){
            rollback(transaction);
            return false;
        }
    }
    transaction->free_locks.push_back(&free_segment->lock);
    transaction->free_segments.push_back(free_segment);
    return true;
}