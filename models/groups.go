package models

import (
	"sort"
	"strings"
)

type AddressGroup struct {
	Name         string   `json:"name" yaml:"name"`
	Members      []string `json:"members" yaml:"members"`
	StaticMembers []string `json:"static_members,omitempty" yaml:"static_members,omitempty"`
	DynamicFilter string  `json:"dynamic_filter,omitempty" yaml:"dynamic_filter,omitempty"`
	Scope        string   `json:"scope" yaml:"scope"`
	DeviceGroup  string   `json:"device_group,omitempty" yaml:"device_group,omitempty"`
	Description  string   `json:"description,omitempty" yaml:"description,omitempty"`
}

type GroupReference struct {
	GroupName    string `json:"group_name" yaml:"group_name"`
	MemberName   string `json:"member_name,omitempty" yaml:"member_name,omitempty"`
	SourceType   string `json:"source_type" yaml:"source_type"`
	SourceName   string `json:"source_name" yaml:"source_name"`
	Context      string `json:"context" yaml:"context"`
	DeviceGroup  string `json:"device_group,omitempty" yaml:"device_group,omitempty"`
	LineNumber   int    `json:"line_number" yaml:"line_number"`
}

type GroupMembership struct {
	GroupName     string   `json:"group_name" yaml:"group_name"`
	MemberName    string   `json:"member_name" yaml:"member_name"`
	MemberType    string   `json:"member_type" yaml:"member_type"`
	GroupScope    string   `json:"group_scope" yaml:"group_scope"`
	DeviceGroup   string   `json:"device_group,omitempty" yaml:"device_group,omitempty"`
	NestedGroups  []string `json:"nested_groups,omitempty" yaml:"nested_groups,omitempty"`
}

type GroupHierarchy struct {
	RootGroups   []string            `json:"root_groups" yaml:"root_groups"`
	GroupTree    map[string][]string `json:"group_tree" yaml:"group_tree"`
	MembershipMap map[string][]string `json:"membership_map" yaml:"membership_map"`
	MaxDepth     int                 `json:"max_depth" yaml:"max_depth"`
}

func (g *AddressGroup) HasMember(memberName string) bool {
	for _, member := range g.Members {
		if member == memberName {
			return true
		}
	}
	
	for _, member := range g.StaticMembers {
		if member == memberName {
			return true
		}
	}
	
	return false
}

func (g *AddressGroup) AddMember(memberName string) {
	if !g.HasMember(memberName) {
		g.Members = append(g.Members, memberName)
		sort.Strings(g.Members)
	}
}

func (g *AddressGroup) RemoveMember(memberName string) {
	g.Members = removeMemberFromSlice(g.Members, memberName)
	g.StaticMembers = removeMemberFromSlice(g.StaticMembers, memberName)
}

func removeMemberFromSlice(slice []string, item string) []string {
	var result []string
	for _, member := range slice {
		if member != item {
			result = append(result, member)
		}
	}
	return result
}

func (g *AddressGroup) GetAllMembers() []string {
	memberSet := make(map[string]bool)
	
	for _, member := range g.Members {
		memberSet[member] = true
	}
	
	for _, member := range g.StaticMembers {
		memberSet[member] = true
	}
	
	var allMembers []string
	for member := range memberSet {
		allMembers = append(allMembers, member)
	}
	
	sort.Strings(allMembers)
	return allMembers
}

func (h *GroupHierarchy) AddGroup(groupName string, members []string) {
	if h.GroupTree == nil {
		h.GroupTree = make(map[string][]string)
	}
	if h.MembershipMap == nil {
		h.MembershipMap = make(map[string][]string)
	}
	
	h.GroupTree[groupName] = append([]string{}, members...)
	
	for _, member := range members {
		h.MembershipMap[member] = append(h.MembershipMap[member], groupName)
	}
}

func (h *GroupHierarchy) GetGroupsContaining(memberName string) []string {
	if h.MembershipMap == nil {
		return nil
	}
	
	groups := h.MembershipMap[memberName]
	result := make([]string, len(groups))
	copy(result, groups)
	sort.Strings(result)
	return result
}

func (h *GroupHierarchy) GetNestedGroups(groupName string, visited map[string]bool) []string {
	if visited == nil {
		visited = make(map[string]bool)
	}
	
	if visited[groupName] {
		return nil
	}
	visited[groupName] = true
	
	var nested []string
	members := h.GroupTree[groupName]
	
	for _, member := range members {
		if strings.HasPrefix(member, "group_") || h.isGroup(member) {
			nested = append(nested, member)
			childNested := h.GetNestedGroups(member, visited)
			nested = append(nested, childNested...)
		}
	}
	
	return nested
}

func (h *GroupHierarchy) isGroup(name string) bool {
	_, exists := h.GroupTree[name]
	return exists
}

func (h *GroupHierarchy) CalculateDepth() {
	h.MaxDepth = 0
	
	for groupName := range h.GroupTree {
		depth := h.calculateGroupDepth(groupName, make(map[string]bool), 0)
		if depth > h.MaxDepth {
			h.MaxDepth = depth
		}
	}
}

func (h *GroupHierarchy) calculateGroupDepth(groupName string, visited map[string]bool, currentDepth int) int {
	if visited[groupName] {
		return currentDepth
	}
	visited[groupName] = true
	
	maxChildDepth := currentDepth
	members := h.GroupTree[groupName]
	
	for _, member := range members {
		if h.isGroup(member) {
			childDepth := h.calculateGroupDepth(member, visited, currentDepth+1)
			if childDepth > maxChildDepth {
				maxChildDepth = childDepth
			}
		}
	}
	
	return maxChildDepth
}