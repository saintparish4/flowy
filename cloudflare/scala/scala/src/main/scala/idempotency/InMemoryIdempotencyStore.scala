package idempotency

import java.time.{Duration, Instant} 
import java.util.concurrent.ConcurrentHashMap
import scala.jdk.CollectionConverters._

/**
  * In-memory implementation of IdempotencyStore using ConcurrentHashMap 
  * 
  * Features:
    * - Thread-safe without global locks 
    * - First writer wins semantics 
    * - Lazy TTL cleanup (expired entries removed on access) 
    * - No partial state - operations are atomic 
    * 
    * Storage format: Map[key -> (response, expiryTime)] 
  */
class InMemoryIdempotencyStore extends IdempotencyStore {

    // Storage: key -> (response, expiry timestamp) 
    private val store = new ConcurrentHashMap[String, (StoredResponse, Instant)]() 

    /**
      * Retrieve a stored response, checking for expiry 
      * 
      * Expired entries are removed lazily during this operation 
      * 
      * @param key The idempotency key 
      * @return Some(response) if exists and not expired, None otherwise 
      */
    override def get(key: String): Option[StoredResponse] = {
        require(key != null, "key cannot be null") 

        val now = Instant.now() 

        Option(store.get(key)) match {
            case Some((response, expiryTime)) => 
                if (now.isBefore(expiryTime)) {
                    // Valid entry - return it 
                    Some(response) 
                } else {
                    // Expired - remove it and return None 
                    store.remove(key, (response, expiryTime))
                    None 
                }

            case None => 
                None 
        }
    }

    /**
      * Store a response only if they key doesn't exist (or has expired) 
      * 
      * This implements first writer wins semantics:
      * - If key doesn't exist: store and return Stored 
      * - If key exists and is valid: return AlreadyExists with existing response 
      * - If key exists but expired: remove old entry and store new one 
      * 
      * Thread-safety: Uses ConcurrentHashMap's atomic operations to ensure 
      * that concurrent writes result in exactly one stored value 
      * 
      * @param key The idempotency key 
      * @param response The response to store 
      * @param ttl Time-to-live for the entry 
      * @return Stored or AlreadyExists(existing response)
      */
    override def putIfAbsent(
        key: String, 
        response: StoredResponse, 
        ttl: Duration 
    ): IdempotencyResult = {
        require(key != null, "key cannot be null") 
        require(response != null, "response cannot be null") 
        require(ttl != null, "ttl cannot be null") 
        require(!ttl.isNegative && !ttl.isZero, "ttl must be positive") 

        val now = Instant.now() 
        val expiryTime = now.plus(ttl) 
        val newEntry = (response, expiryTime)

        // Atomically try to insert - putIfAbsent returns null if we inserted, 
        // or the existing value if someone else inserted first
        val previous = store.putIfAbsent(key, newEntry)
        
        if (previous == null) {
            // We successfully inserted - first writer wins
            Stored
        } else {
            // Someone else inserted first - check if it's still valid
            val (existingResponse, existingExpiry) = previous
            if (now.isBefore(existingExpiry)) {
                // Valid entry exists - return it
                AlreadyExists(existingResponse)
            } else {
                // Previous entry was expired - try to replace it atomically
                val replaced = store.replace(key, previous, newEntry)
                if (replaced) {
                    // Successfully replaced expired entry
                    Stored
                } else {
                    // Someone else updated it between our putIfAbsent and replace
                    // Get the current value and retry
                    get(key) match {
                        case Some(currentResponse) =>
                            // Valid entry now exists
                            AlreadyExists(currentResponse)
                        case None =>
                            // Entry was removed - retry
                            putIfAbsent(key, response, ttl)
                    }
                }
            }
        }
    }

    /**
      * Get the current number of stored entries (including expired ones) 
      * Useful for testing and monitoring 
      * 
      * @return Count og entries in the store 
      */
    def size: Int = store.size() 

    /**
      * Get the number of valid (non-expired) entries 
      * This operation checks all entries for expiry
      * 
      * @return Count of non-expried entries  
      */
    def validSize: Int = {
        val now = Instant.now()
        store.values().asScala.count { case (_, expiryTime) => 
            now.isBefore(expiryTime)
        }
    }

    /**
      * Clear all stored entries 
      * Useful for testing 
      */
    def clear(): Unit = {
        store.clear() 
    }

    /**
      * Manually clean up expired entries 
      * 
      * This is not required for correctness (cleanup happens lazily) 
      * but can be used to reclaim memory 
      * 
      * @return Number of entries removed 
      */
    def cleanupExpired(): Int = {
        val now = Instant.now() 
        var removed = 0 

        store.entrySet().asScala.foreach { entry => 
            val (_, expiryTime) = entry.getValue()
            if (now.isAfter(expiryTime) || now.equals(expiryTime)) {
                if (store.remove(entry.getKey(), entry.getValue())) {
                    removed += 1  
                }
            }
        }

        removed 
    }
}

object InMemoryIdempotencyStore {
    /**
      * Create a new in-memory idempotency store 
      * 
      * @return A new InMemoryIdempotencyStore instance 
      */
    def apply(): InMemoryIdempotencyStore = {
        new InMemoryIdempotencyStore() 
    }
}