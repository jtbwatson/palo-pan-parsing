package cache

import (
	"sync"
	"time"
)

type CacheEntry struct {
	Value      interface{}
	Expiration time.Time
}

type MemoryCache struct {
	data       map[string]CacheEntry
	mutex      sync.RWMutex
	ttl        time.Duration
	maxSize    int
	cleanupInt time.Duration
	stopChan   chan bool
}

func NewMemoryCache(ttl time.Duration, maxSize int) *MemoryCache {
	cache := &MemoryCache{
		data:       make(map[string]CacheEntry),
		ttl:        ttl,
		maxSize:    maxSize,
		cleanupInt: ttl / 2,
		stopChan:   make(chan bool),
	}
	
	go cache.cleanupExpiredEntries()
	
	return cache
}

func (c *MemoryCache) Set(key string, value interface{}) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	
	if len(c.data) >= c.maxSize {
		c.evictOldestEntry()
	}
	
	c.data[key] = CacheEntry{
		Value:      value,
		Expiration: time.Now().Add(c.ttl),
	}
}

func (c *MemoryCache) Get(key string) (interface{}, bool) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	
	entry, exists := c.data[key]
	if !exists {
		return nil, false
	}
	
	if time.Now().After(entry.Expiration) {
		delete(c.data, key)
		return nil, false
	}
	
	return entry.Value, true
}

func (c *MemoryCache) Delete(key string) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	
	delete(c.data, key)
}

func (c *MemoryCache) Clear() {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	
	c.data = make(map[string]CacheEntry)
}

func (c *MemoryCache) Size() int {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	
	return len(c.data)
}

func (c *MemoryCache) Keys() []string {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	
	keys := make([]string, 0, len(c.data))
	for key := range c.data {
		keys = append(keys, key)
	}
	
	return keys
}

func (c *MemoryCache) HasKey(key string) bool {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	
	_, exists := c.data[key]
	return exists
}

func (c *MemoryCache) GetMultiple(keys []string) map[string]interface{} {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	
	results := make(map[string]interface{})
	now := time.Now()
	
	for _, key := range keys {
		if entry, exists := c.data[key]; exists && now.Before(entry.Expiration) {
			results[key] = entry.Value
		}
	}
	
	return results
}

func (c *MemoryCache) SetMultiple(items map[string]interface{}) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	
	expiration := time.Now().Add(c.ttl)
	
	for key, value := range items {
		if len(c.data) >= c.maxSize {
			c.evictOldestEntry()
		}
		
		c.data[key] = CacheEntry{
			Value:      value,
			Expiration: expiration,
		}
	}
}

func (c *MemoryCache) evictOldestEntry() {
	var oldestKey string
	var oldestTime time.Time
	
	for key, entry := range c.data {
		if oldestKey == "" || entry.Expiration.Before(oldestTime) {
			oldestKey = key
			oldestTime = entry.Expiration
		}
	}
	
	if oldestKey != "" {
		delete(c.data, oldestKey)
	}
}

func (c *MemoryCache) cleanupExpiredEntries() {
	ticker := time.NewTicker(c.cleanupInt)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			c.removeExpiredEntries()
		case <-c.stopChan:
			return
		}
	}
}

func (c *MemoryCache) removeExpiredEntries() {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	
	now := time.Now()
	expiredKeys := make([]string, 0)
	
	for key, entry := range c.data {
		if now.After(entry.Expiration) {
			expiredKeys = append(expiredKeys, key)
		}
	}
	
	for _, key := range expiredKeys {
		delete(c.data, key)
	}
}

func (c *MemoryCache) GetStats() map[string]interface{} {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	
	expired := 0
	now := time.Now()
	
	for _, entry := range c.data {
		if now.After(entry.Expiration) {
			expired++
		}
	}
	
	return map[string]interface{}{
		"total_entries":   len(c.data),
		"expired_entries": expired,
		"max_size":        c.maxSize,
		"ttl_seconds":     int(c.ttl.Seconds()),
	}
}

func (c *MemoryCache) Close() {
	close(c.stopChan)
	c.Clear()
}

type CacheManager struct {
	caches map[string]*MemoryCache
	mutex  sync.RWMutex
}

func NewCacheManager() *CacheManager {
	return &CacheManager{
		caches: make(map[string]*MemoryCache),
	}
}

func (cm *CacheManager) GetCache(name string) *MemoryCache {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()
	
	return cm.caches[name]
}

func (cm *CacheManager) CreateCache(name string, ttl time.Duration, maxSize int) *MemoryCache {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()
	
	if existing, exists := cm.caches[name]; exists {
		existing.Close()
	}
	
	cache := NewMemoryCache(ttl, maxSize)
	cm.caches[name] = cache
	
	return cache
}

func (cm *CacheManager) DeleteCache(name string) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()
	
	if cache, exists := cm.caches[name]; exists {
		cache.Close()
		delete(cm.caches, name)
	}
}

func (cm *CacheManager) ClearAllCaches() {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()
	
	for _, cache := range cm.caches {
		cache.Clear()
	}
}

func (cm *CacheManager) CloseAllCaches() {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()
	
	for _, cache := range cm.caches {
		cache.Close()
	}
	
	cm.caches = make(map[string]*MemoryCache)
}

func (cm *CacheManager) GetAllStats() map[string]map[string]interface{} {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()
	
	stats := make(map[string]map[string]interface{})
	
	for name, cache := range cm.caches {
		stats[name] = cache.GetStats()
	}
	
	return stats
}