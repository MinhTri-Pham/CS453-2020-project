/**
 * @file   tm.cpp
 * @author Minh Tri Pham
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

// Shared memory region
struct region {
    void* start; // Start of the shared memory region       
    vector<segment_t*> segments; // Segments belonging to the region
    size_t size;        // Size of the shared memory region (in bytes)
    size_t align;       // Claimed alignment of the shared memory region (in bytes)
};

// Memory segment
struct segment {
    void* start; // Start of the memory segment
    size_t size; // Size of the memory segment (in bytes)
    atomic<int> lock; // Segment lock - has to be claimed for every operation on segment
};

// Transaction    
struct transaction {
    region_t* region; // Shared memory region on which it operates
    bool is_ro;
    vector<atomic<int>*> locks; // Locks that the transaction holds
    vector<segment_t*> alloc_segments; // Segments the transaction wishes to allocate
    vector<segment_t*> free_segments; // Segments the transaction wishes to free
    write_log_t* write_logs; // Write logs of transaction (see next struct)
};

// Linked list of write logs in case we need to rollback
struct write_log {
    void* location; // Address where transaction wants to write
    void* old_data; // Values being overwritten
    size_t size; // Size of write (in bytes)
    struct write_log* next; // Pointer to previous log
};

// --------------- Helper functions ----------------------------------------- //

// Find target segment for read/write/free
segment_t* find_seg(region_t* region, transaction_t* tx, const void* target) {
    // Search in shared memory
    for(auto seg : region->segments) {
        if(target >= seg->start && target < seg->start + seg->size) {
            return seg;
        }
    }
    // Search in segments transaction wishes to allocate
    for(auto seg : tx->alloc_segments) {
        if(target >= seg->start && target < seg->start + seg->size) {
            return seg;
        }
    }
    return NULL; 
}


// Check if a transaction acquired a segment lock
bool have_lock(transaction_t* tx, atomic<int>* lock) {
    for (auto trans_lock : tx->locks) {
        if (trans_lock == lock) return true;
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
    // Unlock locks
    for (auto lock : tx->locks) {
       int expected = 1;
       atomic_compare_exchange_strong(lock, &expected, 0);
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
    if(unlikely(!tx)){
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
    region_t *region = (region_t*) shared;
    transaction_t* transaction = (transaction_t*) tx;
    if (!transaction ->is_ro){
        // Free
        free_segs(transaction, transaction->free_segments);
        // Clean up write logs
        write_log_t* write_log = transaction->write_logs;
        write_log_t* temp;
        while(write_log != NULL){
            free(write_log->old_data);
            temp = write_log->next;
            delete write_log;
            write_log = temp;
        }
        // Commit allocations
        for(auto seg: transaction->alloc_segments) {
            region->segments.push_back(seg);
        }
 
    }
    // Unlock all locks
    for (auto lock : transaction->locks) {
       int expected = 1;
       atomic_compare_exchange_strong(lock, &expected, 0);
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
    segment_t* read_segment = find_seg(region, transaction, source);
    // Rollback if trying to read memory that doesn't exist
    if (!unlikely(read_segment)) {
        rollback(transaction);
        return false;
    }
    // Try to acquire the segment lock unless the transaction already has it
    // Abort if this fails
    if (!have_lock(transaction, &read_segment->lock)){
        int expected = 0;
        if(!atomic_compare_exchange_strong(&read_segment->lock, &expected, 1)){
            rollback(transaction);
            return false;
        } else transaction->locks.push_back(&read_segment->lock);
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
    region_t* region = (region_t*) shared;
    transaction_t* transaction = (transaction_t*) tx;
    segment_t* write_segment = find_seg(region, transaction, target);
    // Rollback if trying to write into memory that doesn't exist
    if (unlikely(!write_segment)) {
        rollback(transaction);
        return false;
    }
    // Try to acquire the segment lock unless the transaction already has it
    // Abort if this fails
    if (!have_lock(transaction, &write_segment->lock)){
        int expected = 0;
        if(!atomic_compare_exchange_strong(&write_segment->lock, &expected, 1)){
            rollback(transaction);
            return false;
        } else {
            transaction->locks.push_back(&write_segment->lock);
        }
    }
    write_log_t* new_log = new write_log_t();
    if (unlikely(!new_log)){
        rollback(transaction);
        return false;
    }
    new_log->old_data = malloc(size);
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
    transaction_t* transaction = (transaction_t*) tx;
    segment_t* new_segment = new segment_t();
    if (unlikely(!new_segment)) {
        return Alloc::nomem;
    }

    if (unlikely(posix_memalign((void**) &(new_segment->start), region->align, size) != 0)){
        delete new_segment;
        return Alloc::nomem;
    }
    memset(new_segment->start, 0, size);
    *target = new_segment->start;
    new_segment->size = size;
    new_segment->lock = 0;
    transaction->alloc_segments.push_back(new_segment);
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
    transaction->locks.push_back(&free_segment->lock);
    transaction->free_segments.push_back(free_segment);
    return true;
}