package processor

import (
	"context"
	"fmt"
	"sync"
	"time"

	"palo-pan-parsing/models"
	"palo-pan-parsing/parser"
)

type Processor struct {
	config              *models.Config
	xmlReader           *parser.XMLReader
	converter           *parser.XMLElementConverter
	filter              *parser.ElementFilter
	analyzer            *Analyzer
	redundancyAnalyzer  *RedundancyAnalyzer
	scopeAnalyzer      *ScopeAnalyzer
	
	results            *models.AnalysisResult
	addressMap         map[string]*models.AddressObject
	groupMap           map[string]*models.AddressGroup
	securityRuleMap    map[string]*models.SecurityRule
	natRuleMap         map[string]*models.NATRule
	
	workerPool         *WorkerPool
	eventChannel       chan parser.XMLEvent
	resultChannel      chan ProcessingResult
	errorChannel       chan error
	
	mutex              sync.RWMutex
	processedLines     int
	startTime          time.Time
}

type ProcessingResult struct {
	Type   string
	Object interface{}
	Error  error
}

type WorkerPool struct {
	workers    int
	jobChannel chan parser.XMLEvent
	wg         sync.WaitGroup
	ctx        context.Context
	cancel     context.CancelFunc
}

func NewProcessor(config *models.Config) *Processor {
	processor := &Processor{
		config:          config,
		xmlReader:       parser.NewXMLReader(config),
		converter:       parser.NewXMLElementConverter(),
		analyzer:        NewAnalyzer(config),
		addressMap:      make(map[string]*models.AddressObject),
		groupMap:        make(map[string]*models.AddressGroup),
		securityRuleMap: make(map[string]*models.SecurityRule),
		natRuleMap:      make(map[string]*models.NATRule),
		eventChannel:    make(chan parser.XMLEvent, 1000),
		resultChannel:   make(chan ProcessingResult, 1000),
		errorChannel:    make(chan error, 100),
	}
	
	if len(config.Addresses) > 0 {
		processor.filter = parser.NewElementFilter(config.Addresses)
	} else if config.TargetAddress != "" {
		processor.filter = parser.NewElementFilter([]string{config.TargetAddress})
	} else {
		processor.filter = parser.NewElementFilter(nil)
	}
	
	processor.redundancyAnalyzer = NewRedundancyAnalyzer(processor)
	processor.scopeAnalyzer = NewScopeAnalyzer(processor)
	
	return processor
}

func (p *Processor) ProcessFile(filename string) (*models.AnalysisResult, error) {
	p.startTime = time.Now()
	
	targetAddress := p.config.TargetAddress
	if targetAddress == "" && len(p.config.Addresses) > 0 {
		targetAddress = p.config.Addresses[0]
	}
	
	p.results = models.NewAnalysisResult(targetAddress, filename)
	
	ctx, cancel := context.WithTimeout(context.Background(), p.config.Timeout)
	defer cancel()
	
	p.workerPool = p.createWorkerPool(ctx)
	
	streamProcessor, err := p.xmlReader.ProcessFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to start XML processing: %w", err)
	}
	defer streamProcessor.Close()
	
	go p.distributeEvents(streamProcessor)
	go p.collectResults()
	
	var processingError error
	done := false
	
	for !done {
		select {
		case <-streamProcessor.Done():
			done = true
		case err := <-streamProcessor.Errors():
			processingError = err
			done = true
		case err := <-p.errorChannel:
			processingError = err
			done = true
		case <-ctx.Done():
			processingError = ctx.Err()
			done = true
		}
	}
	
	p.workerPool.wg.Wait()
	close(p.resultChannel)
	
	if processingError != nil {
		return nil, processingError
	}
	
	p.finalizeResults()
	
	return p.results, nil
}

func (p *Processor) ProcessMultipleAddresses(filename string, addresses []string) (*models.MultiAddressResult, error) {
	multiResult := &models.MultiAddressResult{
		Addresses:         addresses,
		ConfigFile:        filename,
		AnalysisTimestamp: time.Now(),
		Results:          make(map[string]*models.AnalysisResult),
	}
	
	startTime := time.Now()
	
	for _, address := range addresses {
		originalConfig := *p.config
		p.config.TargetAddress = address
		p.config.Addresses = []string{address}
		
		result, err := p.ProcessFile(filename)
		if err != nil {
			return nil, fmt.Errorf("failed to process address %s: %w", address, err)
		}
		
		multiResult.Results[address] = result
		*p.config = originalConfig
		
		p.reset()
	}
	
	multiResult.ProcessingTime = time.Since(startTime)
	p.calculateCombinedStatistics(multiResult)
	
	return multiResult, nil
}

func (p *Processor) createWorkerPool(ctx context.Context) *WorkerPool {
	poolCtx, cancel := context.WithCancel(ctx)
	
	pool := &WorkerPool{
		workers:    p.config.MaxWorkers,
		jobChannel: make(chan parser.XMLEvent, p.config.MaxWorkers*2),
		ctx:        poolCtx,
		cancel:     cancel,
	}
	
	for i := 0; i < pool.workers; i++ {
		pool.wg.Add(1)
		go p.worker(pool, i)
	}
	
	return pool
}

func (p *Processor) worker(pool *WorkerPool, workerID int) {
	defer pool.wg.Done()
	
	for {
		select {
		case event, ok := <-pool.jobChannel:
			if !ok {
				return
			}
			p.processEvent(event)
		case <-pool.ctx.Done():
			return
		}
	}
}

func (p *Processor) distributeEvents(streamProcessor *parser.XMLStreamProcessor) {
	defer close(p.workerPool.jobChannel)
	
	for {
		select {
		case event, ok := <-streamProcessor.Events():
			if !ok {
				return
			}
			
			if p.filter.ShouldProcess(event) {
				p.workerPool.jobChannel <- event
			}
			
		case <-p.workerPool.ctx.Done():
			return
		}
	}
}

func (p *Processor) processEvent(event parser.XMLEvent) {
	result := ProcessingResult{Type: event.Type}
	
	switch event.Type {
	case "address":
		addr, err := p.converter.ConvertToAddressObject(event)
		result.Object = addr
		result.Error = err
		
	case "address_group":
		group, err := p.converter.ConvertToAddressGroup(event)
		result.Object = group
		result.Error = err
		
	case "security_rule":
		rule, err := p.converter.ConvertToSecurityRule(event)
		result.Object = rule
		result.Error = err
		
	case "nat_rule":
		rule, err := p.converter.ConvertToNATRule(event)
		result.Object = rule
		result.Error = err
	}
	
	if result.Error == nil && result.Object != nil {
		p.resultChannel <- result
	} else if result.Error != nil {
		p.errorChannel <- result.Error
	}
	
	p.updateProgress()
}

func (p *Processor) collectResults() {
	for result := range p.resultChannel {
		p.mutex.Lock()
		
		switch result.Type {
		case "address":
			if addr, ok := result.Object.(*models.AddressObject); ok {
				p.addressMap[addr.Name] = addr
				p.results.AddressObjects = append(p.results.AddressObjects, *addr)
				p.results.AddDeviceGroup(addr.DeviceGroup)
				p.results.AddScope(addr.Scope)
			}
			
		case "address_group":
			if group, ok := result.Object.(*models.AddressGroup); ok {
				p.groupMap[group.Name] = group
				p.results.AddressGroups = append(p.results.AddressGroups, *group)
				p.results.AddDeviceGroup(group.DeviceGroup)
				p.results.AddScope(group.Scope)
			}
			
		case "security_rule":
			if rule, ok := result.Object.(*models.SecurityRule); ok {
				p.securityRuleMap[rule.Name] = rule
				p.results.AddDeviceGroup(rule.DeviceGroup)
				p.results.AddScope(rule.Scope)
			}
			
		case "nat_rule":
			if rule, ok := result.Object.(*models.NATRule); ok {
				p.natRuleMap[rule.Name] = rule
				p.results.AddDeviceGroup(rule.DeviceGroup)
				p.results.AddScope(rule.Scope)
			}
		}
		
		p.mutex.Unlock()
	}
}

func (p *Processor) updateProgress() {
	p.mutex.Lock()
	p.processedLines++
	lines := p.processedLines
	p.mutex.Unlock()
	
	if lines%p.config.ProgressEvery == 0 && !p.config.Silent {
		elapsed := time.Since(p.startTime)
		fmt.Printf("\rProcessed %d elements in %v...", lines, elapsed.Truncate(time.Second))
	}
}

func (p *Processor) finalizeResults() {
	p.results.ProcessingTime = time.Since(p.startTime)
	
	p.performAnalysis()
	p.results.CalculateStatistics()
	p.results.SortResults()
	
	if !p.config.Silent {
		fmt.Printf("\nAnalysis completed in %v\n", p.results.ProcessingTime.Truncate(time.Millisecond))
	}
}

func (p *Processor) performAnalysis() {
	if p.analyzer != nil {
		p.analyzer.AnalyzeReferences(p.results, p.addressMap, p.groupMap, p.securityRuleMap, p.natRuleMap)
		p.analyzer.AnalyzeGroupMemberships(p.results, p.groupMap)
	}
	
	if p.redundancyAnalyzer != nil {
		redundantPairs := p.redundancyAnalyzer.FindRedundantAddresses(p.addressMap)
		p.results.RedundantAddresses = redundantPairs
	}
	
	if p.scopeAnalyzer != nil {
		p.scopeAnalyzer.OptimizeScopes(p.results)
	}
	
	// After analysis, populate only relevant address objects and groups
	p.populateRelevantObjects()
}

func (p *Processor) calculateCombinedStatistics(multiResult *models.MultiAddressResult) {
	var stats models.AnalysisStatistics
	
	for _, result := range multiResult.Results {
		stats.AddressObjects += result.Statistics.AddressObjects
		stats.SecurityRules += result.Statistics.SecurityRules
		stats.NATRules += result.Statistics.NATRules
		stats.AddressGroups += result.Statistics.AddressGroups
		stats.DirectReferences += result.Statistics.DirectReferences
		stats.IndirectReferences += result.Statistics.IndirectReferences
		stats.RedundantAddresses += result.Statistics.RedundantAddresses
		
		if result.Statistics.DeviceGroups > stats.DeviceGroups {
			stats.DeviceGroups = result.Statistics.DeviceGroups
		}
	}
	
	multiResult.CombinedStats = stats
}

func (p *Processor) reset() {
	p.addressMap = make(map[string]*models.AddressObject)
	p.groupMap = make(map[string]*models.AddressGroup)
	p.securityRuleMap = make(map[string]*models.SecurityRule)
	p.natRuleMap = make(map[string]*models.NATRule)
	p.processedLines = 0
}

func (p *Processor) GetAddressMap() map[string]*models.AddressObject {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	
	result := make(map[string]*models.AddressObject)
	for k, v := range p.addressMap {
		result[k] = v
	}
	return result
}

func (p *Processor) GetGroupMap() map[string]*models.AddressGroup {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	
	result := make(map[string]*models.AddressGroup)
	for k, v := range p.groupMap {
		result[k] = v
	}
	return result
}

func (p *Processor) GetSecurityRuleMap() map[string]*models.SecurityRule {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	
	result := make(map[string]*models.SecurityRule)
	for k, v := range p.securityRuleMap {
		result[k] = v
	}
	return result
}

func (p *Processor) GetNATRuleMap() map[string]*models.NATRule {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	
	result := make(map[string]*models.NATRule)
	for k, v := range p.natRuleMap {
		result[k] = v
	}
	return result
}

// populateRelevantObjects filters the collected objects to only include those relevant to the analysis
func (p *Processor) populateRelevantObjects() {
	relevantAddresses := make(map[string]bool)
	relevantGroups := make(map[string]bool)
	
	// Add target address
	relevantAddresses[p.results.TargetAddress] = true
	
	// Add addresses from direct references
	for _, ref := range p.results.DirectReferences {
		relevantAddresses[ref.ObjectName] = true
	}
	
	// Add addresses from group memberships
	for _, membership := range p.results.GroupMemberships {
		relevantAddresses[membership.MemberName] = true
		relevantGroups[membership.GroupName] = true
	}
	
	// Add groups from indirect references
	for _, ref := range p.results.IndirectReferences {
		relevantGroups[ref.GroupName] = true
	}
	
	// Add addresses from redundant pairs
	for _, pair := range p.results.RedundantAddresses {
		relevantAddresses[pair.SourceAddress] = true
		relevantAddresses[pair.DuplicateAddress] = true
	}
	
	// Security rules themselves remain intact - they contain valid references to our target
	// We just don't add unrelated addresses from them to the address_objects section
	
	// Filter the existing arrays to keep only relevant objects
	var filteredAddressObjects []models.AddressObject
	for _, addr := range p.results.AddressObjects {
		if relevantAddresses[addr.Name] {
			filteredAddressObjects = append(filteredAddressObjects, addr)
		}
	}
	p.results.AddressObjects = filteredAddressObjects
	
	var filteredAddressGroups []models.AddressGroup
	for _, group := range p.results.AddressGroups {
		if relevantGroups[group.Name] {
			filteredAddressGroups = append(filteredAddressGroups, group)
		}
	}
	p.results.AddressGroups = filteredAddressGroups
}