package tui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// View implements tea.Model
func (m Model) View() string {
	switch m.state {
	case StateMenu:
		return m.viewMenu()
	case StateFileInput:
		return m.viewFileInput()
	case StateAddressInput:
		return m.viewAddressInput()
	case StateDeviceGroupInput:
		return m.viewDeviceGroupInput()
	case StateDeviceGroupSelection:
		return m.viewDeviceGroupSelection()
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
	case StateIPAddressInput:
		return m.viewIPAddressInput()
	case StateCopyAddressInput:
		return m.viewCopyAddressInput()
	case StateCopyNewAddressInput:
		return m.viewCopyNewAddressInput()
	case StateCopyIPAddressInput:
		return m.viewCopyIPAddressInput()
	case StateCopyModeInput:
		return m.viewCopyModeInput()
	case StateOperationStatus:
		return m.viewOperationStatus()
	case StateCompleted:
		return m.viewCompleted()
	case StateError:
		return m.viewError()
	}

	return ""
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
	contentWidth := m.width - (marginHorizontal * 2) - 2 // 2 for border
	contentHeight := m.height - (marginVertical * 2) - 2 // 2 for border

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
	contentHeight := m.height - (marginVertical * 2) - 2 // 2 for border

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