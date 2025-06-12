package parser

import (
	"regexp"
	"strings"
)

type XMLUtils struct {
	patterns map[string]*regexp.Regexp
}

func NewXMLUtils() *XMLUtils {
	return &XMLUtils{
		patterns: map[string]*regexp.Regexp{
			"xml_tag":       regexp.MustCompile(`<([^>]+)>`),
			"entry_name":    regexp.MustCompile(`entry name="([^"]+)"`),
			"member_value":  regexp.MustCompile(`<member>([^<]+)</member>`),
			"tag_content":   regexp.MustCompile(`<([^>]+)>([^<]*)</[^>]+>`),
			"quoted_string": regexp.MustCompile(`"([^"]+)"`),
			"cdata_section": regexp.MustCompile(`<!\[CDATA\[(.*?)\]\]>`),
		},
	}
}

func (u *XMLUtils) ExtractTagName(xmlTag string) string {
	if matches := u.patterns["xml_tag"].FindStringSubmatch(xmlTag); len(matches) > 1 {
		tagName := strings.TrimSpace(matches[1])
		
		if spaceIndex := strings.Index(tagName, " "); spaceIndex != -1 {
			tagName = tagName[:spaceIndex]
		}
		
		return tagName
	}
	return ""
}

func (u *XMLUtils) ExtractEntryName(xmlContent string) string {
	if matches := u.patterns["entry_name"].FindStringSubmatch(xmlContent); len(matches) > 1 {
		return matches[1]
	}
	return ""
}

func (u *XMLUtils) ExtractMembers(xmlContent string) []string {
	var members []string
	matches := u.patterns["member_value"].FindAllStringSubmatch(xmlContent, -1)
	
	for _, match := range matches {
		if len(match) > 1 {
			member := strings.TrimSpace(match[1])
			if member != "" {
				members = append(members, member)
			}
		}
	}
	
	return members
}

func (u *XMLUtils) ExtractTagContent(xmlContent, tagName string) string {
	pattern := regexp.MustCompile(`<` + tagName + `>([^<]*)</` + tagName + `>`)
	if matches := pattern.FindStringSubmatch(xmlContent); len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}
	return ""
}

func (u *XMLUtils) ExtractTagContentMultiple(xmlContent, tagName string) []string {
	pattern := regexp.MustCompile(`<` + tagName + `>([^<]*)</` + tagName + `>`)
	matches := pattern.FindAllStringSubmatch(xmlContent, -1)
	
	var contents []string
	for _, match := range matches {
		if len(match) > 1 {
			content := strings.TrimSpace(match[1])
			if content != "" {
				contents = append(contents, content)
			}
		}
	}
	
	return contents
}

func (u *XMLUtils) ExtractAttributes(xmlTag string) map[string]string {
	attributes := make(map[string]string)
	
	attrPattern := regexp.MustCompile(`(\w+)="([^"]*)"`)
	matches := attrPattern.FindAllStringSubmatch(xmlTag, -1)
	
	for _, match := range matches {
		if len(match) > 2 {
			attributes[match[1]] = match[2]
		}
	}
	
	return attributes
}

func (u *XMLUtils) FindElementSection(xmlContent, elementName string) string {
	startTag := "<" + elementName + ">"
	endTag := "</" + elementName + ">"
	
	startIndex := strings.Index(xmlContent, startTag)
	if startIndex == -1 {
		startTag = "<" + elementName + " "
		startIndex = strings.Index(xmlContent, startTag)
		if startIndex == -1 {
			return ""
		}
		
		tagEndIndex := strings.Index(xmlContent[startIndex:], ">")
		if tagEndIndex == -1 {
			return ""
		}
		startIndex = startIndex + tagEndIndex + 1
	} else {
		startIndex += len(startTag)
	}
	
	endIndex := strings.Index(xmlContent[startIndex:], endTag)
	if endIndex == -1 {
		return ""
	}
	
	return xmlContent[startIndex : startIndex+endIndex]
}

func (u *XMLUtils) IsOpeningTag(line string) bool {
	trimmed := strings.TrimSpace(line)
	return strings.HasPrefix(trimmed, "<") && 
		   !strings.HasPrefix(trimmed, "</") && 
		   !strings.HasPrefix(trimmed, "<!") &&
		   strings.HasSuffix(trimmed, ">")
}

func (u *XMLUtils) IsClosingTag(line string) bool {
	trimmed := strings.TrimSpace(line)
	return strings.HasPrefix(trimmed, "</") && strings.HasSuffix(trimmed, ">")
}

func (u *XMLUtils) IsSelfClosingTag(line string) bool {
	trimmed := strings.TrimSpace(line)
	return strings.HasPrefix(trimmed, "<") && 
		   strings.HasSuffix(trimmed, "/>")
}

func (u *XMLUtils) GetElementDepth(line string) int {
	return strings.Count(line, "\t") + strings.Count(line, "  ")/2
}

func (u *XMLUtils) StripXMLTags(content string) string {
	tagPattern := regexp.MustCompile(`<[^>]*>`)
	return tagPattern.ReplaceAllString(content, "")
}

func (u *XMLUtils) NormalizeWhitespace(content string) string {
	lines := strings.Split(content, "\n")
	var normalizedLines []string
	
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" {
			normalizedLines = append(normalizedLines, trimmed)
		}
	}
	
	return strings.Join(normalizedLines, "\n")
}

func (u *XMLUtils) ExtractCDATA(content string) []string {
	matches := u.patterns["cdata_section"].FindAllStringSubmatch(content, -1)
	var cdataContents []string
	
	for _, match := range matches {
		if len(match) > 1 {
			cdataContents = append(cdataContents, match[1])
		}
	}
	
	return cdataContents
}

func (u *XMLUtils) FindNestedElements(content, elementName string) []string {
	var elements []string
	startTag := "<" + elementName
	endTag := "</" + elementName + ">"
	
	pos := 0
	for {
		startIndex := strings.Index(content[pos:], startTag)
		if startIndex == -1 {
			break
		}
		startIndex += pos
		
		tagEndIndex := strings.Index(content[startIndex:], ">")
		if tagEndIndex == -1 {
			break
		}
		tagEndIndex += startIndex + 1
		
		endIndex := strings.Index(content[tagEndIndex:], endTag)
		if endIndex == -1 {
			break
		}
		endIndex += tagEndIndex
		
		element := content[startIndex : endIndex+len(endTag)]
		elements = append(elements, element)
		
		pos = endIndex + len(endTag)
	}
	
	return elements
}

func (u *XMLUtils) ValidateXMLStructure(content string) bool {
	lines := strings.Split(content, "\n")
	var tagStack []string
	
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		
		if u.IsSelfClosingTag(trimmed) {
			continue
		}
		
		if u.IsOpeningTag(trimmed) {
			tagName := u.ExtractTagName(trimmed)
			if tagName != "" {
				tagStack = append(tagStack, tagName)
			}
		} else if u.IsClosingTag(trimmed) {
			tagName := u.ExtractTagName(trimmed)
			if tagName != "" && len(tagStack) > 0 {
				if tagStack[len(tagStack)-1] == tagName {
					tagStack = tagStack[:len(tagStack)-1]
				} else {
					return false
				}
			}
		}
	}
	
	return len(tagStack) == 0
}

func (u *XMLUtils) EscapeXMLContent(content string) string {
	content = strings.ReplaceAll(content, "&", "&amp;")
	content = strings.ReplaceAll(content, "<", "&lt;")
	content = strings.ReplaceAll(content, ">", "&gt;")
	content = strings.ReplaceAll(content, "\"", "&quot;")
	content = strings.ReplaceAll(content, "'", "&#39;")
	return content
}

func (u *XMLUtils) UnescapeXMLContent(content string) string {
	content = strings.ReplaceAll(content, "&amp;", "&")
	content = strings.ReplaceAll(content, "&lt;", "<")
	content = strings.ReplaceAll(content, "&gt;", ">")
	content = strings.ReplaceAll(content, "&quot;", "\"")
	content = strings.ReplaceAll(content, "&#39;", "'")
	return content
}