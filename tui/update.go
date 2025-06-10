package tui

import (
	tea "github.com/charmbracelet/bubbletea"
)

// Update implements tea.Model
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		return m.handleWindowSize(msg)
	case tea.KeyMsg:
		return m.handleKeyMessage(msg)
	case tea.MouseMsg:
		return m.handleMouseMessage(msg)
	case ProcessResult:
		return m.handleProcessResult(msg)
	case ProcessProgressMsg:
		m.progress = msg.Progress
		return m, nil
	case TickMsg:
		return m.handleTickMessage()
	case ProgressPollMsg:
		return m.handleProgressPoll()
	}

	return m, nil
}

// handleWindowSize handles window resize events
func (m Model) handleWindowSize(msg tea.WindowSizeMsg) (Model, tea.Cmd) {
	m.width = msg.Width
	m.height = msg.Height

	// Calculate pane sizes
	if m.showRightPane {
		m.leftPaneWidth = int(float64(m.width) * 0.6)    // 60% for left pane
		m.rightPaneWidth = m.width - m.leftPaneWidth - 1 // 40% for right pane (minus 1 for separator)
	} else {
		m.leftPaneWidth = m.width
		m.rightPaneWidth = 0
	}

	return m, nil
}

// handleKeyMessage handles keyboard input based on current state
func (m Model) handleKeyMessage(msg tea.KeyMsg) (Model, tea.Cmd) {
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

	// Delegate to state-specific handlers
	switch m.state {
	case StateMenu:
		model, cmd := m.updateMenu(msg)
		return model.(Model), cmd
	case StateFileInput:
		model, cmd := m.updateFileInput(msg)
		return model.(Model), cmd
	case StateAddressInput:
		model, cmd := m.updateAddressInput(msg)
		return model.(Model), cmd
	case StateResults:
		model, cmd := m.updateResults(msg)
		return model.(Model), cmd
	case StatePostAnalysis:
		model, cmd := m.updatePostAnalysis(msg)
		return model.(Model), cmd
	case StateSelectSourceAddress:
		model, cmd := m.updateSelectSourceAddress(msg)
		return model.(Model), cmd
	case StateNewAddressInput:
		model, cmd := m.updateNewAddressInput(msg)
		return model.(Model), cmd
	case StateIPAddressInput:
		model, cmd := m.updateIPAddressInput(msg)
		return model.(Model), cmd
	case StateOperationStatus:
		model, cmd := m.updateOperationStatus(msg)
		return model.(Model), cmd
	case StateCompleted:
		model, cmd := m.updateCompleted(msg)
		return model.(Model), cmd
	case StateError:
		model, cmd := m.updateError(msg)
		return model.(Model), cmd
	}

	return m, nil
}

// handleMouseMessage handles mouse input
func (m Model) handleMouseMessage(msg tea.MouseMsg) (Model, tea.Cmd) {
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

	return m, nil
}

// handleTickMessage handles tick messages for animations
func (m Model) handleTickMessage() (Model, tea.Cmd) {
	if m.state == StateProcessing {
		m.processingDots = (m.processingDots + 1) % 4
		// Also update progress from global state
		m.progress = getProgress()
		return m, tickCmd()
	}
	return m, nil
}

// handleProgressPoll handles progress polling messages
func (m Model) handleProgressPoll() (Model, tea.Cmd) {
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