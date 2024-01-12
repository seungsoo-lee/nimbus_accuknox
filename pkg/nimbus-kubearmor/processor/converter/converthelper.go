// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Nimbus

package converter

import (
	v1 "github.com/5GSEC/nimbus/api/v1"
	ksp "github.com/kubearmor/KubeArmor/pkg/KubeArmorController/api/security.kubearmor.com/v1"
)

// handleProcessPolicy handles the conversion of process-related rules.
func handleProcessPolicy(rule v1.Rule, category string) (ksp.ProcessType, error) {
	processType := ksp.ProcessType{
		MatchPaths:       []ksp.ProcessPathType{},
		MatchDirectories: []ksp.ProcessDirectoryType{},
		MatchPatterns:    []ksp.ProcessPatternType{},
	}

	switch category {
	case "paths":
		// Convert match paths to process paths
		for _, matchPath := range rule.MatchPaths {
			if matchPath.Path != "" {
				processType.MatchPaths = append(processType.MatchPaths, ksp.ProcessPathType{
					Path: ksp.MatchPathType(matchPath.Path),
				})
			}
		}

	case "dirs":
		// Convert match directories to process directories
		for _, matchDir := range rule.MatchDirectories {
			var fromSources []ksp.MatchSourceType
			for _, source := range matchDir.FromSource {
				fromSources = append(fromSources, ksp.MatchSourceType{
					Path: ksp.MatchPathType(source.Path),
				})
			}
			if matchDir.Directory != "" || len(fromSources) > 0 {
				processType.MatchDirectories = append(processType.MatchDirectories, ksp.ProcessDirectoryType{
					Directory:  ksp.MatchDirectoryType(matchDir.Directory),
					FromSource: fromSources,
				})
			}
		}

	case "patterns":
		// Convert match patterns to process patterns
		for _, matchPattern := range rule.MatchPatterns {
			if matchPattern.Pattern != "" {
				processType.MatchPatterns = append(processType.MatchPatterns, ksp.ProcessPatternType{
					Pattern: matchPattern.Pattern,
				})
			}
		}
	}

	// Set empty slices if fields are empty
	if len(processType.MatchPaths) == 0 {
		processType.MatchPaths = []ksp.ProcessPathType{}
	}
	if len(processType.MatchDirectories) == 0 {
		processType.MatchDirectories = []ksp.ProcessDirectoryType{}
	}
	if len(processType.MatchPatterns) == 0 {
		processType.MatchPatterns = []ksp.ProcessPatternType{}
	}

	return processType, nil
}

// handleFilePolicy handles the conversion of file-related rules.
func handleFilePolicy(rule v1.Rule, category string) (ksp.FileType, error) {
	fileType := ksp.FileType{
		MatchPaths:       []ksp.FilePathType{},
		MatchDirectories: []ksp.FileDirectoryType{},
		MatchPatterns:    []ksp.FilePatternType{},
	}

	switch category {
	case "paths":
		// Convert match paths to file paths
		for _, matchPath := range rule.MatchPaths {
			if matchPath.Path != "" {
				fileType.MatchPaths = append(fileType.MatchPaths, ksp.FilePathType{
					Path: ksp.MatchPathType(matchPath.Path),
				})
			}
		}
	case "dirs":
		// Convert match directories to file directories
		for _, matchDir := range rule.MatchDirectories {
			var fromSources []ksp.MatchSourceType
			for _, source := range matchDir.FromSource {
				fromSources = append(fromSources, ksp.MatchSourceType{
					Path: ksp.MatchPathType(source.Path),
				})
			}
			if matchDir.Directory != "" || len(fromSources) > 0 {
				fileType.MatchDirectories = append(fileType.MatchDirectories, ksp.FileDirectoryType{
					Directory:  ksp.MatchDirectoryType(matchDir.Directory),
					FromSource: fromSources,
				})
			}
		}
	case "patterns":
		// Convert match patterns to file patterns
		for _, matchPattern := range rule.MatchPatterns {
			if matchPattern.Pattern != "" {
				fileType.MatchPatterns = append(fileType.MatchPatterns, ksp.FilePatternType{
					Pattern: matchPattern.Pattern,
				})
			}
		}
	}

	// Set empty slices if fields are empty
	if len(fileType.MatchPaths) == 0 {
		fileType.MatchPaths = []ksp.FilePathType{}
	}
	if len(fileType.MatchDirectories) == 0 {
		fileType.MatchDirectories = []ksp.FileDirectoryType{}
	}
	if len(fileType.MatchPatterns) == 0 {
		fileType.MatchPatterns = []ksp.FilePatternType{}
	}

	return fileType, nil
}

// handleNetworkPolicy handles the conversion of network-related rules.
func handleNetworkPolicy(rule v1.Rule) (ksp.NetworkType, error) {
	networkType := ksp.NetworkType{
		MatchProtocols: []ksp.MatchNetworkProtocolType{},
	}

	// Convert match protocols to network protocols
	for _, matchProtocol := range rule.MatchProtocols {
		if matchProtocol.Protocol != "" {
			networkType.MatchProtocols = append(networkType.MatchProtocols, ksp.MatchNetworkProtocolType{
				Protocol: ksp.MatchNetworkProtocolStringType(matchProtocol.Protocol),
			})
		}
	}
	return networkType, nil
}

// handleSyscallPolicy handles the conversion of syscall-related rules.
func handleSyscallPolicy(rule v1.Rule, category string) (ksp.SyscallsType, error) {
	syscallType := ksp.SyscallsType{
		MatchSyscalls: []ksp.SyscallMatchType{},
		MatchPaths:    []ksp.SyscallMatchPathType{},
	}

	switch category {
	case "syscalls":
		// Convert match syscalls to syscall matches
		for _, matchSyscall := range rule.MatchSyscalls {
			syscallMatch := ksp.SyscallMatchType{
				Syscalls: []ksp.Syscall{},
			}
			for _, syscall := range matchSyscall.Syscalls {
				if syscall != "" {
					syscallMatch.Syscalls = append(syscallMatch.Syscalls, ksp.Syscall(syscall))
				}
			}
			syscallType.MatchSyscalls = append(syscallType.MatchSyscalls, syscallMatch)
		}

	case "paths":
		// Convert match syscall paths to syscall path matches
		for _, matchSyscallPath := range rule.MatchSyscallPaths {
			syscallMatchPath := ksp.SyscallMatchPathType{
				Path:       ksp.MatchSyscallPathType(matchSyscallPath.Path),
				Recursive:  matchSyscallPath.Recursive,
				Syscalls:   []ksp.Syscall{},
				FromSource: []ksp.SyscallFromSourceType{},
			}
			for _, syscall := range matchSyscallPath.Syscalls {
				if syscall != "" {
					syscallMatchPath.Syscalls = append(syscallMatchPath.Syscalls, ksp.Syscall(syscall))
				}
			}
			for _, fromSource := range matchSyscallPath.FromSource {
				syscallFromSource := ksp.SyscallFromSourceType{
					Path: ksp.MatchPathType(fromSource.Path),
					Dir:  fromSource.Dir,
				}
				syscallMatchPath.FromSource = append(syscallMatchPath.FromSource, syscallFromSource)
			}
			syscallType.MatchPaths = append(syscallType.MatchPaths, syscallMatchPath)
		}
	}

	// Set empty slices if fields are empty
	if len(syscallType.MatchSyscalls) == 0 {
		syscallType.MatchSyscalls = []ksp.SyscallMatchType{}
	}
	if len(syscallType.MatchPaths) == 0 {
		syscallType.MatchPaths = []ksp.SyscallMatchPathType{}
	}

	return syscallType, nil
}

// handleCapabilityPolicy handles the conversion of capability-related rules.
func handleCapabilityPolicy(rule v1.Rule) (ksp.CapabilitiesType, error) {
	capabilityType := ksp.CapabilitiesType{
		MatchCapabilities: []ksp.MatchCapabilitiesType{},
	}

	// Convert match capabilities to capability matches
	for _, matchCapability := range rule.MatchCapabilities {
		if matchCapability.Capability != "" {
			capabilityType.MatchCapabilities = append(capabilityType.MatchCapabilities, ksp.MatchCapabilitiesType{
				Capability: ksp.MatchCapabilitiesStringType(matchCapability.Capability),
			})
		}
	}
	return capabilityType, nil
}
