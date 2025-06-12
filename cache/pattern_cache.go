package cache

import (
	"regexp"
	"sync"
)

type PatternCache struct {
	patterns map[string]*regexp.Regexp
	mutex    sync.RWMutex
}

func NewPatternCache() *PatternCache {
	return &PatternCache{
		patterns: make(map[string]*regexp.Regexp),
	}
}

func (pc *PatternCache) GetPattern(pattern string) (*regexp.Regexp, error) {
	pc.mutex.RLock()
	if regex, exists := pc.patterns[pattern]; exists {
		pc.mutex.RUnlock()
		return regex, nil
	}
	pc.mutex.RUnlock()
	
	pc.mutex.Lock()
	defer pc.mutex.Unlock()
	
	if regex, exists := pc.patterns[pattern]; exists {
		return regex, nil
	}
	
	regex, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	
	pc.patterns[pattern] = regex
	return regex, nil
}

func (pc *PatternCache) PrecompilePatterns(patterns []string) error {
	pc.mutex.Lock()
	defer pc.mutex.Unlock()
	
	for _, pattern := range patterns {
		if _, exists := pc.patterns[pattern]; !exists {
			regex, err := regexp.Compile(pattern)
			if err != nil {
				return err
			}
			pc.patterns[pattern] = regex
		}
	}
	
	return nil
}

func (pc *PatternCache) Size() int {
	pc.mutex.RLock()
	defer pc.mutex.RUnlock()
	
	return len(pc.patterns)
}

func (pc *PatternCache) Clear() {
	pc.mutex.Lock()
	defer pc.mutex.Unlock()
	
	pc.patterns = make(map[string]*regexp.Regexp)
}

func (pc *PatternCache) HasPattern(pattern string) bool {
	pc.mutex.RLock()
	defer pc.mutex.RUnlock()
	
	_, exists := pc.patterns[pattern]
	return exists
}

type ResultCache struct {
	cache        *MemoryCache
	addressHits  map[string]int
	patternHits  map[string]int
	mutex        sync.RWMutex
}

func NewResultCache(maxSize int) *ResultCache {
	return &ResultCache{
		cache:       NewMemoryCache(0, maxSize),
		addressHits: make(map[string]int),
		patternHits: make(map[string]int),
	}
}

func (rc *ResultCache) CacheAddressResult(address string, result interface{}) {
	rc.cache.Set("addr:"+address, result)
	
	rc.mutex.Lock()
	rc.addressHits[address]++
	rc.mutex.Unlock()
}

func (rc *ResultCache) GetAddressResult(address string) (interface{}, bool) {
	return rc.cache.Get("addr:" + address)
}

func (rc *ResultCache) CachePatternResult(pattern string, content string, matches []string) {
	key := "pattern:" + pattern + ":" + hashString(content)
	rc.cache.Set(key, matches)
	
	rc.mutex.Lock()
	rc.patternHits[pattern]++
	rc.mutex.Unlock()
}

func (rc *ResultCache) GetPatternResult(pattern string, content string) ([]string, bool) {
	key := "pattern:" + pattern + ":" + hashString(content)
	if result, exists := rc.cache.Get(key); exists {
		if matches, ok := result.([]string); ok {
			return matches, true
		}
	}
	return nil, false
}

func (rc *ResultCache) GetHitStats() map[string]interface{} {
	rc.mutex.RLock()
	defer rc.mutex.RUnlock()
	
	topAddresses := getTopEntries(rc.addressHits, 10)
	topPatterns := getTopEntries(rc.patternHits, 10)
	
	return map[string]interface{}{
		"cache_size":      rc.cache.Size(),
		"total_addresses": len(rc.addressHits),
		"total_patterns":  len(rc.patternHits),
		"top_addresses":   topAddresses,
		"top_patterns":    topPatterns,
	}
}

func (rc *ResultCache) Clear() {
	rc.cache.Clear()
	
	rc.mutex.Lock()
	rc.addressHits = make(map[string]int)
	rc.patternHits = make(map[string]int)
	rc.mutex.Unlock()
}

func hashString(s string) string {
	if len(s) > 50 {
		return s[:25] + "..." + s[len(s)-25:]
	}
	return s
}

func getTopEntries(hitMap map[string]int, limit int) []map[string]interface{} {
	type entry struct {
		key   string
		count int
	}
	
	var entries []entry
	for key, count := range hitMap {
		entries = append(entries, entry{key, count})
	}
	
	for i := 0; i < len(entries)-1; i++ {
		for j := i + 1; j < len(entries); j++ {
			if entries[j].count > entries[i].count {
				entries[i], entries[j] = entries[j], entries[i]
			}
		}
	}
	
	if len(entries) > limit {
		entries = entries[:limit]
	}
	
	var result []map[string]interface{}
	for _, entry := range entries {
		result = append(result, map[string]interface{}{
			"name":  entry.key,
			"count": entry.count,
		})
	}
	
	return result
}