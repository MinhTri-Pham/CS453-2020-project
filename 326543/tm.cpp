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
#include <atomic>
#include <map>
#include <set>
#include <chrono>
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
typedef struct versioned_lock versioned_lock_t;
typedef struct transaction transaction_t;
typedef struct write_object write_object_t;

// Represents a shared memory region
struct region {
    void* start;        // Start of the shared memory region
    set<segment_t*> segments; // Segments belonging to the region
    size_t size;        // Size of the shared memory region (in bytes)
    size_t align;       // Claimed alignment of the shared memory region (in bytes)
};

// Represents a memory segment
struct segment {
    void* start; // Start of segment
    map<void*, versioned_lock*> versioned_locks; // Per word versioned locks
    size_t size; // SIze of segment
};

// Represents a versioned lock
struct versioned_lock {  
    timed_mutex lock; // The lock itself 
    atomic<unsigned int> version; // Version of lock
    atomic<bool> is_locked; // Whether lock is acquired
};

// Represents a transaction
struct transaction {
    bool is_ro; // Whether transaction is read_only
    map<void*, segment_t*> read_set; // Read set (map between address and segment)
    map<void*, write_object_t*> write_set; // Write set (map between address and segment, value pair)
    unsigned int rv; // Read version
    unsigned int wv; // Write version
    set<segment_t*> to_alloc; // Segments transaction wants to allocate
    set<segment_t*> to_free; // Segments transaction wants to free
};

// For writes, allocs and frees
struct write_object {
    segment_t* segment; // Segment to which we wish to write
    void* value;  // Value written
    bool is_free; // Whether it is a free
};

// Global version clock
atomic<unsigned int> version_clock{0};

// --------------- Helper functions ----------------------------------------- //

// Find target segment for read/write/free
segment_t *find_target_seg(region_t* region, transaction_t* trans, const void* addr) {
    // Search in shared memory (includes allocated segments by other transactions)
    for(auto seg : region->segments) {
        if(addr >= seg->start && addr < seg->start + seg->size) {
            return seg;
        }
    }
    // Search in segments this transaction wishes to allocated
    for(auto seg : trans->to_alloc) {
        if(addr >= seg->start && addr < seg->start + seg->size) {
            return seg;
        }
    }
    return NULL;
}


// Freeing acquired locks if write set can't be locked at commit time
void free_locks(map<void*, segment_t*> acq_lock_locations) {
    map<void*, segment_t*>::iterator locksIt = acq_lock_locations.begin();
    while(locksIt != acq_lock_locations.end()) {
            void* adrr = locksIt->first;
            segment_t* write_seg = locksIt->second;
            write_seg->versioned_locks[adrr]->is_locked.store(false);
            write_seg->versioned_locks[adrr]->lock->unlock();

    }        
}

// -------------------------------------------------------------------------- //


/** Create (i.e. allocate + init) a new shared memory region, with one first non-free-able allocated segment of the requested size and alignment.
 * @param size  Size of the first shared segment of memory to allocate (in bytes), must be a positive multiple of the alignment
 * @param align Alignment (in bytes, must be a power of 2) that the shared memory region must support
 * @return Opaque shared memory region handle, 'invalid_shared' on failure
**/
shared_t tm_create(size_t size as(unused), size_t align as(unused)) {
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
    // Create per word versioned locks with version 0 and open lock
    for (size_t i = 0; i < size; i+=align) {
        versioned_lock_t* v_lock = new versioned_lock_t();
        v_lock->version.store(0);
        v_lock->is_locked.store(false);
        first->versioned_locks[first->start + i] = v_lock;
    }

    // Init region 
    region->size = size;
    region->align = align;
    region->segments.insert(first);
    return region;

}

/** Destroy (i.e. clean-up + free) a given shared memory region.
 * @param shared Shared memory region to destroy, with no running transaction
**/
void tm_destroy(shared_t shared as(unused)) {
    region_t* region = (region_t*) shared;
    for (auto seg : region->segments){
        // Delete locks
        map<void*, versioned_lock_t*>::iterator locksIt = seg->versioned_locks.begin();
        while(locksIt != seg->versioned_locks.end()) {
            delete locksIt->first;
            delete locksIt->second;
            seg->versioned_locks.erase(locksIt);
        }
        // Delete segment
        delete seg->start;
        delete seg;
    }
    // Delete the region
    delete region->start;
    delete region;
}

/** [thread-safe] Return the start address of the first allocated segment in the shared memory region.
 * @param shared Shared memory region to query
 * @return Start address of the first allocated segment
**/
void* tm_start(shared_t shared as(unused)) {
    return ((region_t*) shared)->start;
}

/** [thread-safe] Return the size (in bytes) of the first allocated segment of the shared memory region.
 * @param shared Shared memory region to query
 * @return First allocated segment size
**/
size_t tm_size(shared_t shared as(unused)) {
    return ((region_t*) shared)->size;
}

/** [thread-safe] Return the alignment (in bytes) of the memory accesses on the given shared memory region.
 * @param shared Shared memory region to query
 * @return Alignment used globally
**/
size_t tm_align(shared_t shared as(unused)) {
    return ((region_t*) shared)->align;
}

/** [thread-safe] Begin a new transaction on the given shared memory region.
 * @param shared Shared memory region to start a transaction on
 * @param is_ro  Whether the transaction is read-only
 * @return Opaque transaction ID, 'invalid_tx' on failure
**/
tx_t tm_begin(shared_t shared as(unused), bool is_ro as(unused)) {
    transaction_t* tx = new transaction_t();
    tx->is_ro = is_ro;
    tx->rv = version_clock.load();
    return (tx_t) tx;
}

/** [thread-safe] End the given transaction.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to end
 * @return Whether the whole transaction committed
**/
bool tm_end(shared_t shared as(unused), tx_t tx as(unused)) {
    region_t* region = (region_t*) shared;
    transaction_t* transaction = (transaction_t*) tx;
    // If transaction is read-only, commit immediately (all necessary checks have already been made in tm_read)
    if (transaction->is_ro) return true;
    // Lock write set and free set
    // Try to acquire each lock within 10 ms, abort the transaction if we fail to do so for any transaction
    chrono::milliseconds acquire_time(10);
    map<void*, segment_t*> acq_lock_locations;
    map<void*, write_object_t*>::iterator wSetIt = transaction->write_set.begin();
    while (wSetIt != transaction->write_set.end()) {
        void* write_addr = wSetIt->first;
        segment_t* write_segment = wSetIt->second->segment;
        if (write_segment->versioned_locks[write_addr]->lock->try_lock_for(acquire_time)) {
            acq_lock_locations.insert({write_addr, write_segment});
            write_segment->versioned_locks[write_addr]->is_locked.store(true);
        }
        else {
            free_locks(acq_lock_locations);
            return false;
        }
        wSetIt++;
    }
    // Increment version clock
    transaction->wv = version_clock++; 
    // Validate read set apart from special case rv + 1 = wv
    if (transaction->rv + 1 != transaction->wv) {
        // This is to ensure memory locations haven't been modified while doing the above two steps
        // (locking the write set and incrementing the version clock)
        map<void*, segment_t*>::iterator rSetIt = transaction->read_set.begin();
        while(rSetIt != transaction->read_set.end()) {
            void* read_addr = rSetIt->first;
            segment_t* read_seg = rSetIt->second;
            // Make the same lock/rv check as in tm_read
            if (read_seg->versioned_locks[read_addr]->is_locked.load() || read_seg->versioned_locks[read_addr]->version > transaction->rv) {
                return false;
            }
            rSetIt++;
        }
    }

    // Commit write set 
    map<void*, write_object_t*>::iterator wSetIt = transaction->write_set.begin();
    while (wSetIt != transaction->write_set.end()) {
        void* write_addr = wSetIt->first;
        segment_t* write_seg = wSetIt->second->segment;
        // Write the new values
        // Set version of lock at this location to wv and clear its locked bit
        memcpy(write_addr, wSetIt->second->value, region->align);
        write_seg->versioned_locks[write_addr]->version.store(transaction->wv);
        write_seg->versioned_locks[write_addr]->is_locked.store(false);
        wSetIt++;
    }
    // Add segments allocated by transaction to shared region
    for (auto seg : transaction->to_alloc) {
        region->segments.insert(seg);
    }
    // Add segments deallocated by transaction to shared region
    for (auto seg : transaction->to_alloc) {
        region->segments.erase(seg);
    }
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
bool tm_read(shared_t shared as(unused), tx_t tx as(unused), void const* source as(unused), size_t size as(unused), void* target as(unused)) {
    region_t* region = (region_t*) shared;
    transaction_t* transaction = (transaction_t*) tx;
    // Iterate through each read memory word
    // Detect if transaction could already be aborted
    // If it can't, copy the region content at this word address or the Write set value associated with the word address
    for(size_t i = 0; i < size; i+=region->align) {
        void* word = const_cast<void*>(source) + i;
        // Find segment read address belongs to
        segment_t* seg = find_target_seg(region, transaction, word);
        if (seg == NULL) return false;
        // Version/lock check (abort if it fails)
        if (seg->versioned_locks[word]->is_locked.load() || seg->versioned_locks[word]->version > transaction->rv) {
            return false;
        }
        else
        {
            transaction->read_set.insert({word, seg}); // Update read set
            // If word address appears in the write set, copy the associated value into the private buffer
            if (transaction->write_set.count(word) == 1) {    
                memcpy(target+i, transaction->write_set[word]->value, region->align);
                break;
            }
            // Otherwise, copy what's in memory into the private buffer
            else
            {
                memcpy(target+i, source+i, region->align);
                break;
            }
        }
    }
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
bool tm_write(shared_t shared as(unused), tx_t tx as(unused), void const* source as(unused), size_t size as(unused), void* target as(unused)) {
    region_t* region = (region_t*) shared;
    transaction_t* transaction = (transaction_t*) tx;
    // Iterate through each word in the source and store address, segment and value written into the write set
    // Don't actually copy into the shared region
    for (size_t i = 0; i < size; i+=region->align) {
        void* word = target + i;
        // Find which segment write address belongs to
        segment_t* seg = find_target_seg(region, transaction, word);
        if (seg == NULL) return false;        
        // Overwrite existing entry or create new entry in the write set
        if (transaction->write_set.count(word) == 1) {
            memcpy(transaction->write_set[word]->value, source+i, region->align);
        }
        else
        {
            write_object_t* w_obj = new write_object_t();
            w_obj->segment = seg;  
            w_obj->is_free = false;
            memcpy(transaction->write_set[word]->value, source+i, region->align);
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
Alloc tm_alloc(shared_t shared as(unused), tx_t tx as(unused), size_t size as(unused), void** target as(unused)) {
    region_t* region = (region_t*) shared;
    transaction_t* trans = (transaction_t*) tx;
    segment_t* alloc_seg = new segment_t();
    size_t align = region->align;
    // Check that memory allocation can be done
    if (unlikely(!alloc_seg)) {
        return Alloc::nomem;
    }
    if (unlikely(posix_memalign(&(alloc_seg->start), align, size) != 0)) {
        return Alloc::nomem;
    }
    alloc_seg->size = size;
    memset(alloc_seg->start, 0, size);
    void* start = alloc_seg->start;
    // Create per word versioned locks with version 0 and open lock for new segment
    // Don't actually update shared memory here, we will do it at commit time if it's possible
    // Instead, update write set with locations and values written (0s) with new segment words
    for (size_t i = 0; i < size; i+=align) {
        versioned_lock_t* v_lock = new versioned_lock_t();
        v_lock->version.store(0);
        v_lock->is_locked.store(false);
        alloc_seg->versioned_locks[start + i] = v_lock;
        write_object_t* w_obj = new write_object_t();
        w_obj->segment = alloc_seg;
        w_obj->is_free = false;
        memcpy(w_obj->value, start + i, align);
        trans->write_set[start+i] = w_obj;
    }
    trans->to_alloc.insert(alloc_seg);
    return Alloc::success;
    
}

/** [thread-safe] Memory freeing in the given transaction.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to use
 * @param target Address of the first byte of the previously allocated segment to deallocate
 * @return Whether the whole transaction can continue
**/
bool tm_free(shared_t shared as(unused), tx_t tx as(unused), void* target as(unused)) {
    region_t* region = (region_t*) shared;
    transaction_t* transaction = (transaction_t*) tx;
    // Find the segment we want to free
    // Search in segments this transaction wishes to allocate
    segment_t* to_free = NULL;
    for(auto seg : transaction->to_alloc) {
        if(target >= seg->start && target < seg->start + seg->size) {
            to_free = seg;
            transaction->to_alloc.erase(seg);
            break;
        }
    }
    // Search in shared memory (includes allocated segments by other transactions)
    for(auto seg : region->segments) {
        if(target >= seg->start && target < seg->start + seg->size) {
            to_free = seg;
            transaction->to_free.insert(seg);
            break;
        }
    }
    if (to_free == NULL) return false; // Tried to free a segment that doesn't exist
    // Delete entries in read and write sets
    // For write set, either delete or add a new entry
    // Don't modify shared memory yet 
    for (int i = 0; i < to_free->size; i+= region->align) {
        void* word = to_free->start + i;
        // Transaction hasn't tried to write to this location yet (allocated by another transaction)
        // Indicate that we wish to free this entry
        if (transaction->write_set.count(word) == 0) {
            write_object_t* w_obj = new write_object_t();
            w_obj->is_free = true;
            w_obj->segment = to_free;
            transaction->write_set[word] = w_obj;
        }
        // Transaction tried to write to this location before during its execution (using write or alloc)
        // Delete corresponding entry in the write set
        if (transaction->write_set.count(word) == 1) {
            map<void*, write_object_t*>::iterator it = transaction->write_set.find(word);
            transaction->write_set.erase(it);
        }
    }

}
