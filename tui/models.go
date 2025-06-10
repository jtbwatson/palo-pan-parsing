package tui

// This file now contains only message handling and utility functions that
// coordinate between the modularized components. All core functionality has
// been moved to focused files:
//
// - state.go: Core types, Model struct, NewModel constructor
// - update.go: Main Update() method and event handling
// - view.go: Main View() method and layout rendering
// - input_states.go: All input state handlers (menu, file, address, new address, IP)
// - analysis_states.go: Processing, results, and post-analysis states
// - operation_states.go: Operation status, completion, and error states
// - session_summary.go: Output summary rendering and session tracking
// - command_generators.go: Command generation and execution logic
// - animation.go: Tick commands and timing utilities

// Any remaining functions here are placeholders for:
// - handleProcessResult (if it exists in the commands.go file)
// - Message type definitions that might be in commands.go
// - Other utility functions that coordinate between modules

// Note: This modularization reduces the original 1,838-line file to 10 focused
// files averaging 150-400 lines each, following Go best practices for
// package organization and single responsibility principle.