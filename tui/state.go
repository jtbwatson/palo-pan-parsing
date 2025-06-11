package tui

import (
	"github.com/charmbracelet/bubbles/progress"
	tea "github.com/charmbracelet/bubbletea"
	"palo-pan-parsing/processor"
)

// AppState represents the current state of the application
type AppState int

const (
	StateMenu AppState = iota
	StateFileInput
	StateAddressInput
	StateDeviceGroupInput
	StateDeviceGroupSelection
	StateProcessing
	StateResults
	StatePostAnalysis
	StateSelectSourceAddress
	StateNewAddressInput
	StateIPAddressInput
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
	logFile           string
	addresses         []string
	addressInput      string
	fileInput         string
	deviceGroupInput  string
	newAddressInput   string
	ipAddressInput    string

	// Device group duplicate scan
	discoveredDeviceGroups []string
	selectedDeviceGroup    string

	// Address group generation
	addressesWithGroups     []string
	selectedSourceAddress   string
	selectedSourceAddresses map[int]bool // Track which source addresses are selected

	// Individual address processing workflow
	addressProcessingQueue []string          // Queue of addresses to process individually
	currentProcessingIndex int               // Current index in the queue
	addressNameMappings    map[string]string // Maps source address to new address name
	addressIPMappings      map[string]string // Maps source address to IP address

	// Configuration cache for efficient multi-device group analysis
	configCache *processor.ConfigurationCache

	// Pending operations
	pendingCommands []tea.Cmd

	// Processing
	progress       float64
	progressBar    progress.Model
	processingDots int

	// Results
	results           string
	analysisResults   map[string]any
	hasAddressGroups  bool
	hasRedundantAddrs bool
	operationMessage  string

	// Operation details for status display
	lastOperationType    string
	lastOperationSummary string
	lastFilesGenerated   []string
	lastAddressMappings  map[string]string
	lastAddresses        []string
	lastConfigFile       string

	// Output summary for right pane
	outputSummary      []string
	outputScrollOffset int

	// Device group selection scrolling
	deviceGroupScrollOffset int

	// Error handling
	err               error
	ipValidationError string

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
		choices:                 []string{"Analyze Configuration File", "Find Duplicate Addresses in Device Group", "Exit"},
		postAnalysisSelected:    make(map[int]bool),
		selectedSourceAddresses: make(map[int]bool),
		addressNameMappings:     make(map[string]string),
		addressIPMappings:       make(map[string]string),
		progressBar:             prog,
		showRightPane:           false,
		outputSummary:           []string{},
		outputScrollOffset:      0,
		deviceGroupScrollOffset: 0,
		leftPaneWidth:           0, // Will be set by window size
		rightPaneWidth:          0,
	}
}

// Init implements tea.Model
func (m Model) Init() tea.Cmd {
	return nil
}