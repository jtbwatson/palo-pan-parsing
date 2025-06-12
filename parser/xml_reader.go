package parser

import (
	"bufio"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"sync"

	"palo-pan-parsing/models"
)

type XMLReader struct {
	config     *models.Config
	patterns   *models.XMLPatterns
	context    *models.ProcessingContext
	bufferPool *sync.Pool
	chunkSize  int
}

type XMLEvent struct {
	Type        string
	Name        string
	Content     string
	LineNumber  int
	Scope       string
	DeviceGroup string
	Attributes  map[string]string
}

type XMLStreamProcessor struct {
	reader     *XMLReader
	eventChan  chan XMLEvent
	errorChan  chan error
	doneChan   chan bool
	ctx        context.Context
	cancel     context.CancelFunc
}

func NewXMLReader(config *models.Config) *XMLReader {
	return &XMLReader{
		config:   config,
		patterns: models.NewXMLPatterns(),
		context:  models.NewProcessingContext(),
		chunkSize: config.BufferSize,
		bufferPool: &sync.Pool{
			New: func() interface{} {
				return make([]byte, config.BufferSize)
			},
		},
	}
}

func (r *XMLReader) ProcessFile(filename string) (*XMLStreamProcessor, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open file %s: %w", filename, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), r.config.Timeout)
	
	processor := &XMLStreamProcessor{
		reader:    r,
		eventChan: make(chan XMLEvent, 1000),
		errorChan: make(chan error, 10),
		doneChan:  make(chan bool, 1),
		ctx:       ctx,
		cancel:    cancel,
	}

	go r.streamProcessFile(file, processor)
	
	return processor, nil
}

func (r *XMLReader) streamProcessFile(file *os.File, processor *XMLStreamProcessor) {
	defer file.Close()
	defer close(processor.eventChan)
	defer close(processor.errorChan)
	defer func() {
		processor.doneChan <- true
		close(processor.doneChan)
	}()

	scanner := bufio.NewScanner(file)
	buffer := r.bufferPool.Get().([]byte)
	defer r.bufferPool.Put(buffer)
	
	scanner.Buffer(buffer, r.config.BufferSize)
	
	var allLines []string
	var lineNumber int
	
	// First, read all lines into memory for easier processing
	for scanner.Scan() {
		select {
		case <-processor.ctx.Done():
			processor.errorChan <- processor.ctx.Err()
			return
		default:
		}
		
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		allLines = append(allLines, line)
		
		if lineNumber%r.config.ProgressEvery == 0 && !r.config.Silent {
			r.reportProgress(lineNumber)
		}
	}
	
	// Now process the content to find entries
	content := strings.Join(allLines, "\n")
	
	// Find address entries
	r.extractAddressEntries(content, processor)
	
	// Find address group entries  
	r.extractAddressGroupEntries(content, processor)
	
	// Find security rule entries
	r.extractSecurityRuleEntries(content, processor)
	
	// Find NAT rule entries
	r.extractNATRuleEntries(content, processor)
	
	if err := scanner.Err(); err != nil {
		processor.errorChan <- fmt.Errorf("error reading file: %w", err)
	}
}

func (r *XMLReader) createAddressEvent(name, content string, lineNumber int) XMLEvent {
	event := XMLEvent{
		Type:        "address",
		Name:        name,
		Content:     content,
		LineNumber:  lineNumber,
		Scope:       r.context.GetFullScope(),
		DeviceGroup: r.context.CurrentDeviceGroup,
		Attributes:  make(map[string]string),
	}
	
	r.extractAddressAttributes(&event, content)
	return event
}

func (r *XMLReader) createGroupEvent(name, content string, lineNumber int) XMLEvent {
	event := XMLEvent{
		Type:        "address_group",
		Name:        name,
		Content:     content,
		LineNumber:  lineNumber,
		Scope:       r.context.GetFullScope(),
		DeviceGroup: r.context.CurrentDeviceGroup,
		Attributes:  make(map[string]string),
	}
	
	r.extractGroupAttributes(&event, content)
	return event
}

func (r *XMLReader) createSecurityRuleEvent(name, content string, lineNumber int) XMLEvent {
	event := XMLEvent{
		Type:        "security_rule",
		Name:        name,
		Content:     content,
		LineNumber:  lineNumber,
		Scope:       r.context.GetFullScope(),
		DeviceGroup: r.context.CurrentDeviceGroup,
		Attributes:  make(map[string]string),
	}
	
	return event
}

func (r *XMLReader) createNATRuleEvent(name, content string, lineNumber int) XMLEvent {
	event := XMLEvent{
		Type:        "nat_rule",
		Name:        name,
		Content:     content,
		LineNumber:  lineNumber,
		Scope:       r.context.GetFullScope(),
		DeviceGroup: r.context.CurrentDeviceGroup,
		Attributes:  make(map[string]string),
	}
	
	return event
}

func (r *XMLReader) extractAddressAttributes(event *XMLEvent, content string) {
	if match := r.patterns.IPNetmask.FindStringSubmatch(content); len(match) > 1 {
		event.Attributes["ip_netmask"] = match[1]
	}
	
	if match := r.patterns.IPRange.FindStringSubmatch(content); len(match) > 1 {
		event.Attributes["ip_range"] = match[1]
	}
	
	if match := r.patterns.FQDN.FindStringSubmatch(content); len(match) > 1 {
		event.Attributes["fqdn"] = match[1]
	}
}

func (r *XMLReader) extractGroupAttributes(event *XMLEvent, content string) {
	members := r.patterns.Member.FindAllStringSubmatch(content, -1)
	var memberList []string
	for _, match := range members {
		if len(match) > 1 {
			memberList = append(memberList, match[1])
		}
	}
	
	if len(memberList) > 0 {
		event.Attributes["members"] = strings.Join(memberList, ",")
	}
}


func (r *XMLReader) updateContext(line string, lineNumber int) {
	r.context.LineNumber = lineNumber
	
	if lineNumber%r.config.ProgressEvery == 0 {
		r.context.ProcessingPhase = fmt.Sprintf("Processing line %d", lineNumber)
	}
}

func (r *XMLReader) extractAddressEntries(content string, processor *XMLStreamProcessor) {
	// Look for address entries: <address><entry name="..." [attributes]>...</entry></address>
	addressPattern := regexp.MustCompile(`(?s)<address>.*?</address>`)
	entryPattern := regexp.MustCompile(`(?s)<entry name="([^"]+)"[^>]*>(.*?)</entry>`)
	
	addressSections := addressPattern.FindAllString(content, -1)
	for _, section := range addressSections {
		entries := entryPattern.FindAllStringSubmatch(section, -1)
		for _, entry := range entries {
			if len(entry) > 2 {
				name := entry[1]
				entryContent := entry[2]
				
				event := r.createAddressEvent(name, entryContent, 0)
				select {
				case processor.eventChan <- event:
				case <-processor.ctx.Done():
					return
				}
			}
		}
	}
}

func (r *XMLReader) extractAddressGroupEntries(content string, processor *XMLStreamProcessor) {
	// Look for address group entries: <address-group><entry name="...">...</entry></address-group>
	groupPattern := regexp.MustCompile(`(?s)<address-group>.*?</address-group>`)
	entryPattern := regexp.MustCompile(`(?s)<entry name="([^"]+)">(.*?)</entry>`)
	
	groupSections := groupPattern.FindAllString(content, -1)
	for _, section := range groupSections {
		entries := entryPattern.FindAllStringSubmatch(section, -1)
		for _, entry := range entries {
			if len(entry) > 2 {
				name := entry[1]
				entryContent := entry[2]
				
				event := r.createGroupEvent(name, entryContent, 0)
				select {
				case processor.eventChan <- event:
				case <-processor.ctx.Done():
					return
				}
			}
		}
	}
}

func (r *XMLReader) extractSecurityRuleEntries(content string, processor *XMLStreamProcessor) {
	// Look for security rule entries: <security><rules><entry name="...">...</entry></rules></security>
	securityPattern := regexp.MustCompile(`(?s)<security>.*?<rules>(.*?)</rules>.*?</security>`)
	entryPattern := regexp.MustCompile(`(?s)<entry name="([^"]+)"[^>]*>(.*?)</entry>`)
	
	securityMatches := securityPattern.FindAllStringSubmatch(content, -1)
	for _, match := range securityMatches {
		if len(match) > 1 {
			rulesSection := match[1]
			entries := entryPattern.FindAllStringSubmatch(rulesSection, -1)
			for _, entry := range entries {
				if len(entry) > 2 {
					name := entry[1]
					entryContent := entry[2]
					
					event := r.createSecurityRuleEvent(name, entryContent, 0)
					select {
					case processor.eventChan <- event:
					case <-processor.ctx.Done():
						return
					}
				}
			}
		}
	}
}

func (r *XMLReader) extractNATRuleEntries(content string, processor *XMLStreamProcessor) {
	// Look for NAT rule entries: <nat><rules><entry name="...">...</entry></rules></nat>
	natPattern := regexp.MustCompile(`(?s)<nat>.*?<rules>(.*?)</rules>.*?</nat>`)
	entryPattern := regexp.MustCompile(`(?s)<entry name="([^"]+)"[^>]*>(.*?)</entry>`)
	
	natMatches := natPattern.FindAllStringSubmatch(content, -1)
	for _, match := range natMatches {
		if len(match) > 1 {
			rulesSection := match[1]
			entries := entryPattern.FindAllStringSubmatch(rulesSection, -1)
			for _, entry := range entries {
				if len(entry) > 2 {
					name := entry[1]
					entryContent := entry[2]
					
					event := r.createNATRuleEvent(name, entryContent, 0)
					select {
					case processor.eventChan <- event:
					case <-processor.ctx.Done():
						return
					}
				}
			}
		}
	}
}

func (r *XMLReader) reportProgress(lineNumber int) {
	if !r.config.Silent {
		fmt.Printf("\rProcessing line %d...", lineNumber)
	}
}

func (p *XMLStreamProcessor) Events() <-chan XMLEvent {
	return p.eventChan
}

func (p *XMLStreamProcessor) Errors() <-chan error {
	return p.errorChan
}

func (p *XMLStreamProcessor) Done() <-chan bool {
	return p.doneChan
}

func (p *XMLStreamProcessor) Close() {
	if p.cancel != nil {
		p.cancel()
	}
}

type ChunkedXMLReader struct {
	reader    *XMLReader
	chunkSize int
}

func NewChunkedXMLReader(config *models.Config, chunkSize int) *ChunkedXMLReader {
	return &ChunkedXMLReader{
		reader:    NewXMLReader(config),
		chunkSize: chunkSize,
	}
}

func (cr *ChunkedXMLReader) ProcessFileInChunks(filename string, handler func([]XMLEvent) error) error {
	processor, err := cr.reader.ProcessFile(filename)
	if err != nil {
		return err
	}
	defer processor.Close()
	
	var batch []XMLEvent
	
	for {
		select {
		case event, ok := <-processor.Events():
			if !ok {
				if len(batch) > 0 {
					if err := handler(batch); err != nil {
						return err
					}
				}
				return nil
			}
			
			batch = append(batch, event)
			
			if len(batch) >= cr.chunkSize {
				if err := handler(batch); err != nil {
					return err
				}
				batch = batch[:0]
			}
			
		case err := <-processor.Errors():
			return err
			
		case <-processor.Done():
			if len(batch) > 0 {
				return handler(batch)
			}
			return nil
		}
	}
}

func ParseXMLTokens(content string) ([]xml.Token, error) {
	decoder := xml.NewDecoder(strings.NewReader(content))
	decoder.CharsetReader = func(charset string, input io.Reader) (io.Reader, error) {
		return input, nil
	}
	
	var tokens []xml.Token
	
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		
		tokens = append(tokens, xml.CopyToken(token))
	}
	
	return tokens, nil
}