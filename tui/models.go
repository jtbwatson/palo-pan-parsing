package tui

import (
	"fmt"
	"strings"
	"time"

	"palo-pan-parsing/processor"

	"github.com/charmbracelet/bubbles/progress"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// AppState represents the current state of the application
type AppState int

const (
	StateMenu AppState = iota
	StateFileInput
	StateAddressInput
	StateProcessing
	StateResults
	StatePostAnalysis
	StateSelectSourceAddress
	StateNewAddressInput
	StateOperationStatus
	StateCompleted
	StateError
)

// Model represents the main TUI model
type Model struct {
	state  AppState
	width  int
	height int

	// Pane layout
	leftPaneWidth  int
	rightPaneWidth int
	showRightPane  bool

	// Input fields
	logFile         string
	addresses       []string
	addressInput    string
	fileInput       string
	newAddressInput string

	// Address group generation
	addressesWithGroups     []string
	selectedSourceAddress   string
	selectedSourceAddresses map[int]bool // Track which source addresses are selected
	
	// Individual address processing workflow
	addressProcessingQueue []string      // Queue of addresses to process individually
	currentProcessingIndex int           // Current index in the queue
	addressNameMappings    map[string]string // Maps source address to new address name

	// Pending operations
	pendingCommands []tea.Cmd

	// Processing
	progress    float64
	progressBar progress.Model
	processingDots int

	// Results
	results           string
	analysisResults   map[string]any
	hasAddressGroups  bool
	hasRedundantAddrs bool
	operationMessage  string
	
	// Operation details for status display
	lastOperationType     string
	lastOperationSummary  string
	lastFilesGenerated    []string
	lastAddressMappings   map[string]string
	lastAddresses         []string
	lastConfigFile        string

	// Output summary for right pane
	outputSummary       []string
	outputScrollOffset int

	// Error handling
	err error

	// UI components
	cursor               int
	selected             map[int]struct{}
	choices              []string
	postAnalysisChoices  []string
	postAnalysisSelected map[int]bool // Track which post-analysis options are selected
}

// NewModel creates a new TUI model
func NewModel() Model {
	prog := progress.New(progress.WithDefaultGradient())
	return Model{
		state:                   StateMenu,
		selected:                make(map[int]struct{}),
		choices:                 []string{"Analyze Configuration File", "Exit"},
		postAnalysisSelected:    make(map[int]bool),
		selectedSourceAddresses: make(map[int]bool),
		addressNameMappings:     make(map[string]string),
		progressBar:             prog,
		showRightPane:           false,
		outputSummary:           []string{},
		outputScrollOffset:      0,
		leftPaneWidth:           0, // Will be set by window size
		rightPaneWidth:          0,
	}
}

// Init implements tea.Model
func (m Model) Init() tea.Cmd {
	return nil
}

// Update implements tea.Model
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		
		// Calculate pane sizes
		if m.showRightPane {
			m.leftPaneWidth = int(float64(m.width) * 0.6)  // 60% for left pane
			m.rightPaneWidth = m.width - m.leftPaneWidth - 1 // 40% for right pane (minus 1 for separator)
		} else {
			m.leftPaneWidth = m.width
			m.rightPaneWidth = 0
		}

	case tea.KeyMsg:
		// Handle global scroll keys for right pane when it's visible
		if m.showRightPane {
			switch msg.String() {
			case "pgup", "ctrl+u":
				if m.outputScrollOffset > 0 {
					m.outputScrollOffset -= 5
					if m.outputScrollOffset < 0 {
						m.outputScrollOffset = 0
					}
				}
				return m, nil
			case "pgdn", "ctrl+d":
				maxScroll := len(m.outputSummary) - 10 // Approximate visible lines
				if maxScroll < 0 {
					maxScroll = 0
				}
				if m.outputScrollOffset < maxScroll {
					m.outputScrollOffset += 5
					if m.outputScrollOffset > maxScroll {
						m.outputScrollOffset = maxScroll
					}
				}
				return m, nil
			}
		}
		
		switch m.state {
		case StateMenu:
			return m.updateMenu(msg)
		case StateFileInput:
			return m.updateFileInput(msg)
		case StateAddressInput:
			return m.updateAddressInput(msg)
		case StateResults:
			return m.updateResults(msg)
		case StatePostAnalysis:
			return m.updatePostAnalysis(msg)
		case StateSelectSourceAddress:
			return m.updateSelectSourceAddress(msg)
		case StateNewAddressInput:
			return m.updateNewAddressInput(msg)
		case StateOperationStatus:
			return m.updateOperationStatus(msg)
		case StateCompleted:
			return m.updateCompleted(msg)
		case StateError:
			return m.updateError(msg)
		}

	case tea.MouseMsg:
		// Handle mouse wheel scrolling for right pane when visible
		if m.showRightPane {
			switch msg.Type {
			case tea.MouseWheelUp:
				if m.outputScrollOffset > 0 {
					m.outputScrollOffset -= 2 // Scroll up 2 lines
					if m.outputScrollOffset < 0 {
						m.outputScrollOffset = 0
					}
				}
				return m, nil
			case tea.MouseWheelDown:
				maxScroll := len(m.outputSummary) - 10 // Approximate visible lines
				if maxScroll < 0 {
					maxScroll = 0
				}
				if m.outputScrollOffset < maxScroll {
					m.outputScrollOffset += 2 // Scroll down 2 lines
					if m.outputScrollOffset > maxScroll {
						m.outputScrollOffset = maxScroll
					}
				}
				return m, nil
			}
		}

	case ProcessResult:
		return m.handleProcessResult(msg)
	case ProcessProgressMsg:
		m.progress = msg.Progress
		return m, nil
	case TickMsg:
		if m.state == StateProcessing {
			m.processingDots = (m.processingDots + 1) % 4
			// Also update progress from global state
			m.progress = getProgress()
			return m, tickCmd()
		}
		return m, nil
	case ProgressPollMsg:
		if m.state == StateProcessing {
			// Update progress from global state
			m.progress = getProgress()
			
			// Check if processing is complete
			done, result := getProcessingStatus()
			if done && result != nil {
				return m.handleProcessResult(*result)
			}
			
			// Continue polling
			return m, checkProcessingCompleteCmd()
		}
		return m, nil
	}

	return m, nil
}

// renderWithDynamicWidth renders content with two-pane layout
func (m Model) renderWithDynamicWidth(content string) string {
	if m.width > 0 && m.height > 0 {
		if m.showRightPane && m.leftPaneWidth > 0 && m.rightPaneWidth > 0 {
			return m.renderTwoPaneLayout(content)
		} else {
			return m.renderSinglePaneLayout(content)
		}
	}
	
	// Fallback to original style if dimensions not set
	return boxStyle.Render(content)
}

// renderSinglePaneLayout renders content in single pane mode
func (m Model) renderSinglePaneLayout(content string) string {
	// Leave some margin around the edges for visual breathing room
	marginHorizontal := 2
	marginVertical := 1
	
	// Calculate content area leaving margins
	contentWidth := m.width - (marginHorizontal * 2) - 2  // 2 for border
	contentHeight := m.height - (marginVertical * 2) - 2  // 2 for border
	
	// Ensure minimum usable size
	if contentWidth < 50 {
		contentWidth = 50
	}
	if contentHeight < 10 {
		contentHeight = 10
	}
	
	// Create the main content box
	mainStyle := lipgloss.NewStyle().
		Width(contentWidth).
		Height(contentHeight).
		Padding(1, 2).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(secondaryColor).
		Align(lipgloss.Left)
	
	// Wrap in a positioning style to add the margins
	return lipgloss.NewStyle().
		Width(m.width).
		Height(m.height).
		Padding(marginVertical, marginHorizontal).
		Render(mainStyle.Render(content))
}

// renderTwoPaneLayout renders content with left and right panes
func (m Model) renderTwoPaneLayout(content string) string {
	marginVertical := 1
	contentHeight := m.height - (marginVertical * 2) - 2  // 2 for border
	
	if contentHeight < 10 {
		contentHeight = 10
	}
	
	// Calculate pane widths more simply
	leftWidth := m.leftPaneWidth - 4   // Account for border and padding
	rightWidth := m.rightPaneWidth - 4 // Account for border and padding
	
	// Left pane (main content)
	leftPaneStyle := lipgloss.NewStyle().
		Width(leftWidth).
		Height(contentHeight).
		Padding(1).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(secondaryColor)
	
	leftPane := leftPaneStyle.Render(content)
	
	// Right pane (output summary)  
	rightPaneStyle := lipgloss.NewStyle().
		Width(rightWidth).
		Height(contentHeight).
		Padding(1).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(secondaryColor)
	
	rightPane := rightPaneStyle.Render(m.renderOutputSummary())
	
	// Combine panes horizontally
	combinedPanes := lipgloss.JoinHorizontal(lipgloss.Top, leftPane, " ", rightPane)
	
	// Wrap with positioning
	return lipgloss.NewStyle().
		Padding(marginVertical, 1).
		Render(combinedPanes)
}

// wrapText wraps text to fit within the specified width
func (m Model) wrapText(text string, width int) []string {
	if len(text) <= width {
		return []string{text}
	}
	
	var lines []string
	words := strings.Fields(text)
	var currentLine strings.Builder
	
	for _, word := range words {
		// If adding this word would exceed the width, start a new line
		if currentLine.Len() > 0 && currentLine.Len()+len(word)+1 > width {
			lines = append(lines, currentLine.String())
			currentLine.Reset()
		}
		
		if currentLine.Len() > 0 {
			currentLine.WriteString(" ")
		}
		currentLine.WriteString(word)
	}
	
	if currentLine.Len() > 0 {
		lines = append(lines, currentLine.String())
	}
	
	return lines
}

// renderOutputSummary generates the content for the right pane with scrolling
func (m Model) renderOutputSummary() string {
	var s strings.Builder
	
	// Title for the output summary pane
	s.WriteString(highlightStyle.Render("Session Summary") + "\n\n")
	
	if len(m.outputSummary) == 0 {
		s.WriteString(helpStyle.Render("No operations completed yet.\n\nAnalysis results and operations\nwill appear here as you\nprogress through the workflow."))
	} else {
		// Calculate visible area (approximate based on height)
		visibleLines := m.height - 8 // Account for borders, padding, title
		if visibleLines < 5 {
			visibleLines = 5
		}
		
		// Apply scroll offset
		startIdx := m.outputScrollOffset
		endIdx := startIdx + visibleLines
		
		if startIdx >= len(m.outputSummary) {
			startIdx = len(m.outputSummary) - 1
			if startIdx < 0 {
				startIdx = 0
			}
		}
		
		if endIdx > len(m.outputSummary) {
			endIdx = len(m.outputSummary)
		}
		
		// Render visible lines
		for i := startIdx; i < endIdx; i++ {
			if i < len(m.outputSummary) {
				s.WriteString(m.outputSummary[i])
				if i < endIdx-1 {
					s.WriteString("\n")
				}
			}
		}
		
		// Add scroll indicator if content is scrollable
		if len(m.outputSummary) > visibleLines {
			s.WriteString("\n\n" + helpStyle.Render("PgUp/PgDn, Ctrl+U/D, or mouse wheel to scroll"))
		}
	}
	
	return s.String()
}

// addToOutputSummary adds an item to the output summary
func (m *Model) addToOutputSummary(item string) {
	m.outputSummary = append(m.outputSummary, item)
}

// clearOutputSummary clears the output summary
func (m *Model) clearOutputSummary() {
	m.outputSummary = []string{}
	m.outputScrollOffset = 0
}

// formatSessionAction formats an action description with italic styling
func formatSessionAction(action string) string {
	return sessionActionStyle.Render(action)
}

// formatSessionStatus formats a status line with key: value format and intelligent coloring
func formatSessionStatus(key, value string) string {
	keyStyled := sessionStatusStyle.Render(key + ": ")
	valueStyled := determineValueStyle(key, value).Render(value)
	return keyStyled + valueStyled
}

// determineValueStyle intelligently determines the appropriate style for a status value
func determineValueStyle(key, value string) lipgloss.Style {
	// Convert to lowercase for easier comparison
	lowerKey := strings.ToLower(key)
	lowerValue := strings.ToLower(value)
	
	// Handle special cases first before pattern matching
	switch lowerKey {
	case "redundant addresses":
		// Redundant addresses should always be warning colored
		return sessionWarningValueStyle
	case "target address":
		// Target addresses should be success colored (actual address names)
		return sessionSuccessValueStyle
	case "file", "targets":
		// File names and target addresses should be warning colored
		return sessionWarningValueStyle
	case "files generated", "cleanup commands":
		// Non-zero counts should be success colored
		if lowerValue != "0" && lowerValue != "" {
			return sessionSuccessValueStyle
		}
	}
	
	// Success indicators (green)
	successPatterns := []string{
		"complete", "completed", "success", "successful", "found", "generated", "created", "finished",
	}
	for _, pattern := range successPatterns {
		if strings.Contains(lowerValue, pattern) || strings.Contains(lowerKey, pattern) {
			return sessionSuccessValueStyle
		}
	}
	
	// Error indicators (red)
	errorPatterns := []string{
		"error", "failed", "failure", "not found", "missing", "invalid", "corrupt",
	}
	for _, pattern := range errorPatterns {
		if strings.Contains(lowerValue, pattern) || strings.Contains(lowerKey, pattern) {
			return sessionErrorValueStyle
		}
	}
	
	// Warning indicators (yellow)
	warningPatterns := []string{
		"warning", "partial", "limited", "timeout", "retry", "skipped",
	}
	for _, pattern := range warningPatterns {
		if strings.Contains(lowerValue, pattern) || strings.Contains(lowerKey, pattern) {
			return sessionWarningValueStyle
		}
	}
	
	// Additional special logic for remaining keys
	switch lowerKey {
	case "total references", "addresses", "address groups":
		// Numbers and "Found" should be success colored
		if lowerValue == "found" || (lowerValue != "0" && lowerValue != "") {
			return sessionSuccessValueStyle
		}
	}
	
	// Default neutral styling
	return sessionNeutralValueStyle
}

// addFormattedAction adds a formatted action to the output summary
func (m *Model) addFormattedAction(action string) {
	m.addToOutputSummary(formatSessionAction(action))
}

// addFormattedStatus adds a formatted status line to the output summary
func (m *Model) addFormattedStatus(key, value string) {
	m.addToOutputSummary(formatSessionStatus(key, value))
}

// addFormattedStatusIndented adds a formatted status line with indentation
func (m *Model) addFormattedStatusIndented(key, value string) {
	m.addToOutputSummary("  " + formatSessionStatus(key, value))
}

// addFormattedMapping adds a formatted address mapping line
func (m *Model) addFormattedMapping(source, target string) {
	sourceStyled := sessionNeutralValueStyle.Render(source)
	arrowStyled := sessionStatusStyle.Render(" → ")
	targetStyled := sessionSuccessValueStyle.Render(target)
	m.addToOutputSummary("  " + sourceStyled + arrowStyled + targetStyled)
}

// addFormattedLine adds a formatted line by parsing key: value pairs
func (m *Model) addFormattedLine(line string, indented bool) {
	line = strings.TrimSpace(line)
	if strings.Contains(line, ":") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			if indented {
				m.addFormattedStatusIndented(key, value)
			} else {
				m.addFormattedStatus(key, value)
			}
			return
		}
	}
	// Fallback for lines that don't match key:value format
	if indented {
		m.addToOutputSummary("  " + line)
	} else {
		m.addToOutputSummary(line)
	}
}

// View implements tea.Model
func (m Model) View() string {
	switch m.state {
	case StateMenu:
		return m.viewMenu()
	case StateFileInput:
		return m.viewFileInput()
	case StateAddressInput:
		return m.viewAddressInput()
	case StateProcessing:
		return m.viewProcessing()
	case StateResults:
		return m.viewResults()
	case StatePostAnalysis:
		return m.viewPostAnalysis()
	case StateSelectSourceAddress:
		return m.viewSelectSourceAddress()
	case StateNewAddressInput:
		return m.viewNewAddressInput()
	case StateOperationStatus:
		return m.viewOperationStatus()
	case StateCompleted:
		return m.viewCompleted()
	case StateError:
		return m.viewError()
	}

	return ""
}

// Menu state handlers
func (m Model) updateMenu(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c", "q":
		return m, tea.Quit
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < len(m.choices)-1 {
			m.cursor++
		}
	case "enter", " ":
		switch m.cursor {
		case 0: // Analyze Configuration File
			m.state = StateFileInput
			// Don't pre-populate fileInput - leave empty for placeholder
		case 1: // Exit
			return m, tea.Quit
		}
	}

	return m, nil
}

func (m Model) viewMenu() string {
	var s strings.Builder

	// Header
	title := titleStyle.Render("PAN Configuration Log Parser (Go Edition)")
	subtitle := subtitleStyle.Render("Advanced Palo Alto Networks Configuration Analysis")

	s.WriteString(title + "\n")
	s.WriteString(subtitle + "\n")

	// Menu options with descriptions
	descriptions := []string{
		"Search for address objects and analyze their usage across configuration",
		"Exit the application",
	}

	for i, choice := range m.choices {
		cursor := " "
		if m.cursor == i {
			cursor = ">"
			choice = selectedStyle.Render(choice)
		} else {
			choice = choiceStyle.Render(choice)
		}
		s.WriteString(cursor + " " + choice + "\n")
		// Add description immediately below each option with proper indentation
		if i < len(descriptions) {
			s.WriteString("   " + helpStyle.Render(descriptions[i]) + "\n")
		}
		s.WriteString("\n") // Extra spacing between option groups
	}

	s.WriteString(helpStyle.Render("Use ↑/↓ to navigate, Enter to select, q to quit"))

	return m.renderWithDynamicWidth(s.String())
}

// File input state handlers
func (m Model) updateFileInput(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c":
		return m, tea.Quit
	case "esc":
		m.state = StateMenu
	case "enter":
		if m.fileInput != "" {
			m.logFile = m.fileInput
		} else {
			m.logFile = "default.log" // Use default when field is empty
		}
		// Enable right pane and add initial summary  
		m.showRightPane = true
		// Calculate pane sizes immediately if we have width
		if m.width > 0 {
			m.leftPaneWidth = int(float64(m.width) * 0.6)  // 60% for left pane
			m.rightPaneWidth = m.width - m.leftPaneWidth - 1 // 40% for right pane (minus 1 for separator)
		}
		m.clearOutputSummary()
		m.addFormattedAction("Configuration Analysis Started")
		m.addFormattedStatus("File", m.logFile)
		m.state = StateAddressInput
	case "backspace":
		if len(m.fileInput) > 0 {
			m.fileInput = m.fileInput[:len(m.fileInput)-1]
		}
	default:
		if len(msg.String()) == 1 {
			m.fileInput += msg.String()
		}
	}

	return m, nil
}

func (m Model) viewFileInput() string {
	var s strings.Builder

	title := titleStyle.Render("Configuration File Selection")
	s.WriteString(title + "\n")

	s.WriteString("Enter the path to your PAN configuration file:\n")
	s.WriteString(helpStyle.Render("Supports both local files and full file paths") + "\n\n")

	// Clean input styling with placeholder support
	cursor := "█"
	
	if m.fileInput == "" {
		// Show placeholder text when field is empty
		s.WriteString(inputFieldStyle.Render("File: ") + placeholderStyle.Render("default.log") + cursor + "\n\n")
	} else {
		// Show actual input text
		s.WriteString(inputFieldStyle.Render("File: ") + inputTextStyle.Render(m.fileInput) + cursor + "\n\n")
	}

	s.WriteString(helpStyle.Render("Enter to continue, Esc to go back, Ctrl+C to quit"))

	return m.renderWithDynamicWidth(s.String())
}

// Address input state handlers
func (m Model) updateAddressInput(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c":
		return m, tea.Quit
	case "esc":
		m.state = StateFileInput
	case "enter":
		if m.addressInput != "" {
			// Parse comma-separated addresses
			addresses := strings.Split(m.addressInput, ",")
			m.addresses = make([]string, 0, len(addresses))
			for _, addr := range addresses {
				if trimmed := strings.TrimSpace(addr); trimmed != "" {
					m.addresses = append(m.addresses, trimmed)
				}
			}
			if len(m.addresses) > 0 {
				// Add to output summary
				m.addFormattedAction("Processing Started")
				m.addFormattedStatus("Targets", strings.Join(m.addresses, ", "))
				
				// Start processing
				m.state = StateProcessing
				m.processingDots = 0
				return m, tea.Batch(
					processFileCmd(m.logFile, m.addresses),
					tickCmd(),
				)
			}
		}
	case "backspace":
		if len(m.addressInput) > 0 {
			m.addressInput = m.addressInput[:len(m.addressInput)-1]
		}
	default:
		if len(msg.String()) == 1 {
			m.addressInput += msg.String()
		}
	}

	return m, nil
}

func (m Model) viewAddressInput() string {
	var s strings.Builder

	title := titleStyle.Render("Address Object Selection")
	s.WriteString(title + "\n")

	s.WriteString("Enter address object name(s) to analyze:\n")
	s.WriteString(helpStyle.Render("Use commas to separate multiple addresses (e.g., web1,db1,server2)") + "\n\n")

	// Clean input styling - just highlight the text, no messy boxes
	displayText := m.addressInput
	cursor := "█"
	if displayText == "" {
		// Show placeholder when empty
		s.WriteString("Address(es): " + cursor + "\n\n")
	} else {
		s.WriteString(inputFieldStyle.Render("Address(es): ") + inputTextStyle.Render(displayText) + cursor + "\n\n")
	}

	s.WriteString("Configuration file: " + highlightStyle.Render(m.logFile) + "\n\n")

	s.WriteString(helpStyle.Render("Enter to analyze, Esc to go back, Ctrl+C to quit"))

	return m.renderWithDynamicWidth(s.String())
}

// Processing state
func (m Model) viewProcessing() string {
	var s strings.Builder

	title := titleStyle.Render("Processing Configuration...")
	s.WriteString(title + "\n\n")

	s.WriteString("Analyzing: " + highlightStyle.Render(strings.Join(m.addresses, ", ")) + "\n")
	s.WriteString("File: " + highlightStyle.Render(m.logFile) + "\n\n")

	// Animated progress indicator
	dots := strings.Repeat(".", m.processingDots)
	spaces := strings.Repeat(" ", 3-m.processingDots)
	progressText := "Working" + dots + spaces
	s.WriteString(progressText + "\n\n")

	// Progress bar (if we have progress)
	if m.progress > 0 {
		s.WriteString(m.progressBar.ViewAs(m.progress) + "\n")
		percentage := int(m.progress * 100)
		s.WriteString(fmt.Sprintf("Progress: %d%%\n\n", percentage))
	} else {
		s.WriteString("Initializing analysis...\n\n")
	}

	s.WriteString(helpStyle.Render("Please wait while we analyze your configuration..."))

	return m.renderWithDynamicWidth(s.String())
}

// Results state handlers
func (m Model) updateResults(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c", "q":
		return m, tea.Quit
	case "esc":
		m.state = StateMenu
		// Reset for next analysis
		m.fileInput = ""
		m.addressInput = ""
		m.addresses = nil
		m.results = ""
	}

	return m, nil
}

func (m Model) viewResults() string {
	var s strings.Builder

	title := titleStyle.Render("Analysis Complete")
	s.WriteString(title + "\n\n")

	s.WriteString("Analysis results have been generated:\n\n")

	if len(m.addresses) == 1 {
		filename := m.addresses[0] + "_results.yml"
		s.WriteString("📄 " + highlightStyle.Render("outputs/"+filename) + "\n")
	} else {
		s.WriteString("📄 Multiple result files generated in " + highlightStyle.Render("outputs/") + " directory\n")
		for _, addr := range m.addresses {
			s.WriteString("   • " + addr + "_results.yml\n")
		}
	}

	s.WriteString("\n" + successStyle.Render("✅ Configuration analysis completed successfully!") + "\n\n")

	s.WriteString(helpStyle.Render("Esc to return to menu, q to quit"))

	return m.renderWithDynamicWidth(s.String())
}

// Post-analysis state handlers
func (m Model) updatePostAnalysis(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c", "q":
		return m, tea.Quit
	case "esc":
		m.state = StateResults
	case "up", "k":
		for {
			if m.cursor > 0 {
				m.cursor--
				// Skip separator lines
				if m.postAnalysisChoices[m.cursor] != "---" {
					break
				}
			} else {
				break
			}
		}
	case "down", "j":
		for {
			if m.cursor < len(m.postAnalysisChoices)-1 {
				m.cursor++
				// Skip separator lines
				if m.postAnalysisChoices[m.cursor] != "---" {
					break
				}
			} else {
				break
			}
		}
	case " ": // Spacebar toggles selection
		choice := m.postAnalysisChoices[m.cursor]
		// Only allow selection of operation choices, not separators or action items
		if choice == "Generate Address Group Commands" || choice == "Generate Cleanup Commands" {
			m.postAnalysisSelected[m.cursor] = !m.postAnalysisSelected[m.cursor]
		}
	case "enter":
		choice := m.postAnalysisChoices[m.cursor]
		switch choice {
		case "Execute Selected Operations":
			return m.executeSelectedOperations()
		case "No Additional Options":
			return m.showComprehensiveAnalysisSummary()
		case "Return to Main Menu":
			m.state = StateMenu
			// Reset for next analysis
			m.fileInput = ""
			m.addressInput = ""
			m.addresses = nil
			m.results = ""
			m.cursor = 0
			m.postAnalysisSelected = make(map[int]bool)
			// Clear operation details
			m.lastOperationType = ""
			m.lastOperationSummary = ""
			m.lastFilesGenerated = nil
			// Reset right pane
			m.showRightPane = false
			m.clearOutputSummary()
		}
	}

	return m, nil
}

// executeSelectedOperations runs all selected operations in sequence
func (m Model) executeSelectedOperations() (Model, tea.Cmd) {
	var cmds []tea.Cmd
	var selectedOps []string
	var needsAddressInput bool

	for i, choice := range m.postAnalysisChoices {
		if m.postAnalysisSelected[i] {
			selectedOps = append(selectedOps, choice)
			switch choice {
			case "Generate Address Group Commands":
				// This operation requires new address name input
				needsAddressInput = true
			case "Generate Cleanup Commands":
				if proc, ok := m.analysisResults["processor"].(*processor.PANLogProcessor); ok {
					if configFile, ok := m.analysisResults["configFile"].(string); ok {
						if addresses, ok := m.analysisResults["addresses"].([]string); ok {
							// Generate cleanup commands for all addresses that have redundant addresses
							for _, address := range addresses {
								if _, exists := proc.Results[address]; exists {
									itemsDict := proc.FormatResults(address)
									if len(itemsDict.RedundantAddresses) > 0 {
										cmds = append(cmds, generateCleanupCmd(proc, configFile, address))
									}
								}
							}
						}
					}
				}
			}
		}
	}

	// If Generate Address Group Commands is selected, handle address selection
	if needsAddressInput {
		// Store any other pending commands to execute after address input
		m.pendingCommands = cmds

		if len(m.addressesWithGroups) == 1 {
			// Only one address has groups, go directly to new address input
			m.selectedSourceAddress = m.addressesWithGroups[0]
			m.selectedSourceAddresses = make(map[int]bool)
			m.selectedSourceAddresses[0] = true
			m.state = StateNewAddressInput
			m.newAddressInput = ""
		} else if len(m.addressesWithGroups) > 1 {
			// Multiple addresses have groups, let user choose
			m.state = StateSelectSourceAddress
			m.cursor = 0
			// Clear any previous selections
			m.selectedSourceAddresses = make(map[int]bool)
		} else {
			// No addresses with groups (shouldn't happen)
			m.operationMessage = "No addresses with address groups found"
			m.state = StateOperationStatus
		}
		return m, nil
	}

	if len(cmds) == 0 {
		// No operations selected - show message and stay in current state
		m.operationMessage = "No operations selected. Use Space to select operations first."
		m.state = StateOperationStatus
		return m, nil
	}

	// Reset accumulated operation details before starting new operations
	// (Only reset for the operation status display, not the session summary)
	m.lastOperationType = ""
	m.lastOperationSummary = ""
	m.lastFilesGenerated = nil
	m.lastAddressMappings = nil
	
	// Set status message for operations being executed
	if len(selectedOps) == 1 {
		m.operationMessage = "Executing: " + selectedOps[0]
	} else {
		m.operationMessage = "Executing " + strings.Join(selectedOps, " and ")
	}
	m.state = StateOperationStatus

	// Execute commands (sequentially if multiple, to ensure all results are captured)
	if len(cmds) == 1 {
		return m, cmds[0]
	} else if len(cmds) > 1 {
		// For multiple commands, execute the first one and store the rest for sequential execution
		m.pendingCommands = cmds[1:] // Store remaining commands
		return m, cmds[0] // Execute first command
	}

	return m, nil
}

func (m Model) viewPostAnalysis() string {
	var s strings.Builder

	title := titleStyle.Render("Additional Options")
	s.WriteString(title + "\n")

	s.WriteString("Analysis complete! Select operations to perform:\n\n")

	// Menu options with checkboxes
	for i, choice := range m.postAnalysisChoices {
		cursor := " "
		if m.cursor == i {
			cursor = ">"
		}

		// Handle different types of items
		if choice == "---" {
			s.WriteString("  ────────────────────────────────\n")
			continue
		}

		var line string

		if choice == "Generate Address Group Commands" || choice == "Generate Cleanup Commands" {
			// Selectable operations with consistent spacing
			var checkbox string
			if m.postAnalysisSelected[i] {
				checkbox = "[✓]"
			} else {
				checkbox = "[ ]"
			}

			var displayChoice string
			if m.cursor == i {
				displayChoice = selectedStyle.Render(choice)
			} else {
				displayChoice = choiceStyle.Render(choice)
			}

			line = cursor + " " + checkbox + " " + displayChoice

			// Add description below selectable operations
			var description string
			switch choice {
			case "Generate Address Group Commands":
				description = "Add a new address to the same groups as an existing address"
			case "Generate Cleanup Commands":
				description = "Remove redundant address objects and optimize configuration"
			}

			s.WriteString(line + "\n")
			if description != "" {
				s.WriteString("       " + helpStyle.Render(description) + "\n")
			}
			continue
		} else {
			// Action items (Execute, No Additional Options, Return to Menu) - align with checkbox text
			var displayChoice string
			if m.cursor == i {
				displayChoice = selectedStyle.Render(choice)
			} else {
				displayChoice = choiceStyle.Render(choice)
			}

			// cursor(2) + checkbox(4) + space(1) = 7 total characters to align with
			line = cursor + "   • " + displayChoice // 5 spaces to align properly
			
			// Add description for No Additional Options
			// if choice == "No Additional Options" {
			// 	s.WriteString(line + "\n")
			// 	s.WriteString("       " + helpStyle.Render("View comprehensive analysis summary with all results") + "\n")
			// 	continue
			// }
		}

		s.WriteString(line + "\n")
	}

	s.WriteString("\n" + helpStyle.Render("↑/↓ navigate • Space to select • Enter to execute • Esc to go back"))

	return m.renderWithDynamicWidth(s.String())
}

// Operation status state handlers
func (m Model) updateOperationStatus(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c", "q":
		return m, tea.Quit
	case "enter", "esc", " ":
		// Any key returns to post-analysis menu
		m.state = StatePostAnalysis
		m.operationMessage = ""
	}

	return m, nil
}

func (m Model) viewOperationStatus() string {
	var s strings.Builder

	title := titleStyle.Render("Operation Status")
	s.WriteString(title + "\n\n")

	if m.operationMessage != "" {
		if strings.Contains(m.operationMessage, "No operations selected") {
			s.WriteString(warningStyle.Render(m.operationMessage) + "\n\n")
		} else {
			// Show success message
			s.WriteString(successStyle.Render("✅ " + m.operationMessage) + "\n\n")
			
			// Show detailed operation summary if available
			if m.lastOperationType != "" {
				s.WriteString(highlightStyle.Render("Operation: ") + m.lastOperationType + "\n\n")
				
				// Show configuration file if available
				if m.lastConfigFile != "" {
					s.WriteString(highlightStyle.Render("Configuration File: ") + m.lastConfigFile + "\n\n")
				}
				
				// Show addresses analyzed if available
				if len(m.lastAddresses) > 0 {
					s.WriteString(highlightStyle.Render("Addresses: ") + strings.Join(m.lastAddresses, ", ") + "\n\n")
				}
				
				// Show address mappings if available (for address group operations)
				if len(m.lastAddressMappings) > 0 {
					s.WriteString(highlightStyle.Render("Address Mappings:") + "\n")
					for source, target := range m.lastAddressMappings {
						s.WriteString("  " + source + " → " + target + "\n")
					}
					s.WriteString("\n")
				}
				
				if m.lastOperationSummary != "" {
					s.WriteString(highlightStyle.Render("Summary:") + "\n")
					
					// Process summary line by line for proper indentation and wrapping
					summaryLines := strings.Split(strings.TrimSpace(m.lastOperationSummary), "\n")
					for _, line := range summaryLines {
						line = strings.TrimSpace(line)
						if line != "" {
							// Handle long lines by wrapping them
							maxLineLength := 80
							if m.width > 0 {
								maxLineLength = m.width - 20 // Leave room for indentation and borders
								if maxLineLength < 40 {
									maxLineLength = 40
								}
							}
							
							if len(line) <= maxLineLength {
								if strings.HasPrefix(line, "•") || strings.HasPrefix(line, "-") {
									s.WriteString("  " + line + "\n")
								} else if strings.Contains(line, ":") && !strings.HasPrefix(line, " ") {
									s.WriteString(line + "\n")
								} else {
									s.WriteString("  " + line + "\n")
								}
							} else {
								// Wrap long lines
								wrapped := m.wrapText(line, maxLineLength)
								for i, wrappedLine := range wrapped {
									if i == 0 {
										if strings.HasPrefix(line, "•") || strings.HasPrefix(line, "-") {
											s.WriteString("  " + wrappedLine + "\n")
										} else if strings.Contains(line, ":") && !strings.HasPrefix(line, " ") {
											s.WriteString(wrappedLine + "\n")
										} else {
											s.WriteString("  " + wrappedLine + "\n")
										}
									} else {
										s.WriteString("    " + wrappedLine + "\n") // Extra indent for continuation
									}
								}
							}
						}
					}
					s.WriteString("\n")
				}
				
				if len(m.lastFilesGenerated) > 0 {
					s.WriteString(highlightStyle.Render("Files Generated:") + "\n")
					for _, file := range m.lastFilesGenerated {
						// Show just the filename without redundant outputs/ prefix
						cleanFile := strings.TrimPrefix(file, "outputs/")
						s.WriteString("  📄 " + cleanFile + "\n")
					}
					s.WriteString("\n")
				}
			}
		}
	}

	s.WriteString(helpStyle.Render("Press any key to return to Additional Options menu, q to quit"))

	return m.renderWithDynamicWidth(s.String())
}

// Completion state handlers
func (m Model) updateCompleted(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c", "q":
		return m, tea.Quit
	case "enter", "esc", " ":
		// Return to main menu for new analysis
		m.state = StateMenu
		// Clear session data for fresh start
		m.clearOutputSummary()
		m.addresses = []string{}
		m.logFile = ""
		m.fileInput = ""
		m.addressInput = ""
		m.showRightPane = false
	}

	return m, nil
}

func (m Model) viewCompleted() string {
	var s strings.Builder

	// Responsive header based on terminal width
	if m.width >= 60 {
		// Full-width header for larger terminals
		headerBox := `
╔════════════════════════════════════════════════════════╗
║                                                        ║
║                       THANK YOU!                       ║
║                                                        ║
║                ALL OPERATIONS COMPLETED!               ║
║                                                        ║
╚════════════════════════════════════════════════════════╝`
		s.WriteString(successStyle.Render(headerBox))
	} else if m.width >= 45 {
		// Compact header for medium terminals
		compactHeader := `
╔═══════════════════════════════════════╗
║                                       ║
║               THANK YOU!              ║
║                                       ║
║          OPERATIONS COMPLETED!        ║
║                                       ║
╚═══════════════════════════════════════╝`
		s.WriteString(successStyle.Render(compactHeader))
	} else {
		// Minimal header for very small terminals
		minimalHeader := `
┌─────────────────────────────┐
│                             │
│         THANK YOU!          │
│                             │
│     OPERATIONS COMPLETE!    │
│                             │
└─────────────────────────────┘`
		s.WriteString(successStyle.Render(minimalHeader))
	}
	
	s.WriteString("\n\n")

	// Main title
	summaryMsg := titleStyle.Render("🚀 Analysis Complete!")
	s.WriteString(summaryMsg + "\n\n")

	// Stats summary
	totalFiles := len(m.lastFilesGenerated)
	if totalFiles > 0 {
		statsMsg := fmt.Sprintf("✨ Generated %d output files in the outputs/ directory", totalFiles)
		s.WriteString(successStyle.Render(statsMsg) + "\n")
	}

	if len(m.addresses) > 0 {
		addressMsg := fmt.Sprintf("🎯 Analyzed %d address object(s): %s", len(m.addresses), strings.Join(m.addresses, ", "))
		s.WriteString(highlightStyle.Render(addressMsg) + "\n")
	}

	if m.logFile != "" {
		fileMsg := fmt.Sprintf("📄 Configuration file: %s", m.logFile)
		s.WriteString(sessionStatusStyle.Render(fileMsg) + "\n\n")
	}

	// Thank you message
	thankYouMsg := `Thank you for using the PAN Configuration Log Parser!

Your analysis results have been saved and are ready for review.
All configuration dependencies, address groups, and security rules 
have been thoroughly analyzed and documented.

Happy network administration! 🌐`

	s.WriteString(helpStyle.Render(thankYouMsg) + "\n\n")

	// Action prompt
	s.WriteString(highlightStyle.Render("Press Enter to start a new analysis, or q to quit"))

	return m.renderWithDynamicWidth(s.String())
}

// Error state handlers
func (m Model) updateError(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c", "q":
		return m, tea.Quit
	case "esc":
		m.state = StateMenu
		// Reset error state
		m.err = nil
		m.fileInput = ""
		m.addressInput = ""
		m.addresses = nil
	}

	return m, nil
}

func (m Model) viewError() string {
	var s strings.Builder

	title := errorTitleStyle.Render("Error")
	s.WriteString(title + "\n\n")

	if m.err != nil {
		s.WriteString(errorStyle.Render(m.err.Error()) + "\n\n")
	}

	s.WriteString(helpStyle.Render("Esc to return to menu, q to quit"))

	return m.renderWithDynamicWidth(s.String())
}

// New address input state handlers
func (m Model) updateNewAddressInput(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c":
		return m, tea.Quit
	case "esc":
		m.state = StatePostAnalysis
		m.newAddressInput = ""
		m.pendingCommands = nil // Clear pending commands when canceling
	case "enter":
		if m.newAddressInput != "" {
			// Save the current address mapping
			if len(m.addressProcessingQueue) > 0 && m.currentProcessingIndex < len(m.addressProcessingQueue) {
				currentAddress := m.addressProcessingQueue[m.currentProcessingIndex]
				m.addressNameMappings[currentAddress] = m.newAddressInput
				
				// Move to next address or finish processing
				m.currentProcessingIndex++
				if m.currentProcessingIndex < len(m.addressProcessingQueue) {
					// More addresses to process, continue to next one
					m.newAddressInput = ""
					// Stay in StateNewAddressInput for next address
				} else {
					// All addresses processed, generate commands for all mappings
					return m.generateAllAddressGroupCommands()
				}
			} else {
				// Fallback for single address (backward compatibility)
				return m.generateSingleAddressGroupCommand()
			}
		}
	case "backspace":
		if len(m.newAddressInput) > 0 {
			m.newAddressInput = m.newAddressInput[:len(m.newAddressInput)-1]
		}
	default:
		if len(msg.String()) == 1 {
			m.newAddressInput += msg.String()
		}
	}

	return m, nil
}

func (m Model) viewNewAddressInput() string {
	var s strings.Builder

	title := titleStyle.Render("New Address Name")
	s.WriteString(title + "\n")

	// Show current address being processed and progress
	if len(m.addressProcessingQueue) > 0 && m.currentProcessingIndex < len(m.addressProcessingQueue) {
		currentAddress := m.addressProcessingQueue[m.currentProcessingIndex]
		progress := fmt.Sprintf("(%d of %d)", m.currentProcessingIndex+1, len(m.addressProcessingQueue))
		
		s.WriteString(fmt.Sprintf("Processing address %s: %s\n", progress, highlightStyle.Render(currentAddress)))
		s.WriteString("Enter the name for the new address object:\n")
		s.WriteString(fmt.Sprintf("(This will be added to the same groups as %s)\n\n", currentAddress))
	} else {
		// Fallback for single address (backward compatibility)
		selectedAddresses := []string{}
		for i, selected := range m.selectedSourceAddresses {
			if selected && i < len(m.addressesWithGroups) {
				selectedAddresses = append(selectedAddresses, m.addressesWithGroups[i])
			}
		}
		
		if len(selectedAddresses) > 0 {
			s.WriteString(fmt.Sprintf("Source address: %s\n", highlightStyle.Render(selectedAddresses[0])))
		}
		s.WriteString("Enter the name for the new address object:\n")
		s.WriteString("(This will be added to the same groups as the source address)\n\n")
	}

	// Clean input styling
	displayText := m.newAddressInput
	cursor := "█"
	if displayText == "" {
		s.WriteString("New Address Name: " + placeholderStyle.Render("my-new-address") + "\n\n")
	} else {
		s.WriteString(inputFieldStyle.Render("New Address Name: ") + inputTextStyle.Render(displayText) + cursor + "\n\n")
	}

	s.WriteString(helpStyle.Render("Enter to continue, Esc to go back, Ctrl+C to quit"))

	return m.renderWithDynamicWidth(s.String())
}

// Source address selection state handlers
func (m Model) updateSelectSourceAddress(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c":
		return m, tea.Quit
	case "esc":
		m.state = StatePostAnalysis
		m.pendingCommands = nil // Clear pending commands when canceling
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < len(m.addressesWithGroups)-1 {
			m.cursor++
		}
	case " ": // Spacebar to toggle selection
		if m.cursor < len(m.addressesWithGroups) {
			m.selectedSourceAddresses[m.cursor] = !m.selectedSourceAddresses[m.cursor]
		}
	case "enter":
		// Build queue of selected addresses for individual processing
		m.addressProcessingQueue = []string{}
		for i, selected := range m.selectedSourceAddresses {
			if selected && i < len(m.addressesWithGroups) {
				m.addressProcessingQueue = append(m.addressProcessingQueue, m.addressesWithGroups[i])
			}
		}
		
		if len(m.addressProcessingQueue) > 0 {
			// Start processing the first address
			m.currentProcessingIndex = 0
			m.addressNameMappings = make(map[string]string) // Reset mappings
			m.state = StateNewAddressInput
			m.newAddressInput = ""
		}
	}

	return m, nil
}

func (m Model) viewSelectSourceAddress() string {
	var s strings.Builder

	title := titleStyle.Render("Select Source Addresses")
	s.WriteString(title + "\n\n")

	s.WriteString("Multiple addresses have address groups. Select which ones to use as sources:\n\n")

	for i, address := range m.addressesWithGroups {
		cursor := "  "
		if i == m.cursor {
			cursor = "> "
		}

		// Checkbox indicator (matching post-analysis style)
		var checkbox string
		if m.selectedSourceAddresses[i] {
			checkbox = "[✓]"
		} else {
			checkbox = "[ ]"
		}

		line := cursor + " " + checkbox + " " + address
		if i == m.cursor {
			s.WriteString(selectedStyle.Render(line) + "\n")
		} else {
			s.WriteString(choiceStyle.Render(line) + "\n")
		}
	}

	// Show count of selected items
	selectedCount := 0
	for _, selected := range m.selectedSourceAddresses {
		if selected {
			selectedCount++
		}
	}

	s.WriteString("\n" + helpStyle.Render(fmt.Sprintf("Selected: %d | ↑/↓ to navigate, Space to toggle, Enter to continue, Esc to go back", selectedCount)))

	return m.renderWithDynamicWidth(s.String())
}

// showComprehensiveAnalysisSummary displays a comprehensive summary of the analysis
func (m Model) showComprehensiveAnalysisSummary() (Model, tea.Cmd) {
	// Create comprehensive summary from analysis results
	if analysisResults, ok := m.analysisResults["processor"].(*processor.PANLogProcessor); ok {
		if addresses, ok := m.analysisResults["addresses"].([]string); ok {
			if configFile, ok := m.analysisResults["configFile"].(string); ok {
				// Store comprehensive analysis summary
				m.lastOperationType = "Analysis Summary"
				m.lastConfigFile = configFile
				m.lastAddresses = addresses
				
				// Generate comprehensive summary
				var summaryBuilder strings.Builder
				summaryBuilder.WriteString(fmt.Sprintf("Configuration File: %s\n", configFile))
				summaryBuilder.WriteString(fmt.Sprintf("Addresses Analyzed: %s\n", strings.Join(addresses, ", ")))
				
				// Count total findings
				totalMatches := 0
				addressGroupCount := 0
				redundantAddressCount := 0
				var allFiles []string
				
				for _, address := range addresses {
					if result, exists := analysisResults.Results[address]; exists {
						totalMatches += len(result.MatchingLines)
					}
					
					// Check for additional analysis results
					itemsDict := analysisResults.FormatResults(address)
					addressGroupCount += len(itemsDict.AddressGroups)
					redundantAddressCount += len(itemsDict.RedundantAddresses)
					
					// Add result file
					resultFile := fmt.Sprintf("%s_results.yml", address)
					allFiles = append(allFiles, resultFile)
				}
				
				summaryBuilder.WriteString(fmt.Sprintf("Total Configuration References: %d\n", totalMatches))
				if addressGroupCount > 0 {
					summaryBuilder.WriteString(fmt.Sprintf("Address Groups Found: %d\n", addressGroupCount))
				}
				if redundantAddressCount > 0 {
					summaryBuilder.WriteString(fmt.Sprintf("Redundant Addresses Found: %d", redundantAddressCount))
				}
				
				m.lastOperationSummary = summaryBuilder.String()
				m.lastFilesGenerated = allFiles
				m.operationMessage = "Analysis completed successfully!"
				m.state = StateCompleted
				return m, nil
			}
		}
	}
	
	// Fallback if analysis results not available
	m.lastOperationType = "Analysis Summary"
	m.lastOperationSummary = "Analysis completed - see result files for details"
	m.operationMessage = "Analysis completed successfully!"
	m.state = StateCompleted
	return m, nil
}

// TickMsg is sent periodically for animations
type TickMsg time.Time

// tickCmd returns a command that sends periodic tick messages
func tickCmd() tea.Cmd {
	return tea.Tick(500*time.Millisecond, func(t time.Time) tea.Msg {
		return TickMsg(t)
	})
}

// checkProcessingCompleteCmd checks if processing is complete
func checkProcessingCompleteCmd() tea.Cmd {
	return tea.Tick(100*time.Millisecond, func(t time.Time) tea.Msg {
		return ProgressPollMsg{}
	})
}

// generateAllAddressGroupCommands generates commands for all address mappings
func (m Model) generateAllAddressGroupCommands() (Model, tea.Cmd) {
	if proc, ok := m.analysisResults["processor"].(*processor.PANLogProcessor); ok {
		newModel := m
		newModel.state = StateOperationStatus
		newModel.operationMessage = fmt.Sprintf("Executing operations for %d address mappings...", len(m.addressNameMappings))

		// Create a sequential command to process all mappings
		cmd := generateSequentialAddressGroupCommands(proc, m.addressNameMappings, m.pendingCommands)
		// DON'T clear pending commands - they need to be executed after address group commands complete
		// newModel.pendingCommands = nil // Keep pending commands for later execution
		return newModel, cmd
	}
	
	// Fallback to operation status with error
	newModel := m
	newModel.state = StateOperationStatus
	newModel.operationMessage = "Error: Could not generate address group commands"
	return newModel, nil
}

// generateSingleAddressGroupCommand generates command for single address (backward compatibility)
func (m Model) generateSingleAddressGroupCommand() (Model, tea.Cmd) {
	if proc, ok := m.analysisResults["processor"].(*processor.PANLogProcessor); ok {
		var sourceAddress string
		
		// Find the selected source address
		for i, selected := range m.selectedSourceAddresses {
			if selected && i < len(m.addressesWithGroups) {
				sourceAddress = m.addressesWithGroups[i]
				break
			}
		}
		
		if sourceAddress != "" {
			cmd := generateAddressGroupCmdWithName(proc, sourceAddress, m.newAddressInput)
			newModel := m
			newModel.state = StateOperationStatus
			newModel.operationMessage = "Executing address group operation..."

			// If we have pending commands, execute them all together
			if len(m.pendingCommands) > 0 {
				// Add the address group command to pending commands
				allCmds := append([]tea.Cmd{cmd}, m.pendingCommands...)
				newModel.pendingCommands = nil // Clear pending commands
				return newModel, tea.Batch(allCmds...)
			} else {
				// Just execute the address group command
				return newModel, cmd
			}
		}
	}
	
	// Fallback to operation status with error
	newModel := m
	newModel.state = StateOperationStatus
	newModel.operationMessage = "Error: Could not generate address group command"
	return newModel, nil
}
