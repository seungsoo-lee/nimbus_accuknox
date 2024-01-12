// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Nimbus

package nimbuspolicybuilder

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
	ctrl "sigs.k8s.io/controller-runtime"

	v1 "github.com/5GSEC/nimbus/api/v1"
	"github.com/5GSEC/nimbus/pkg/processor/intentbinder"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// NimbusPolicyBuilder is responsible for building NimbusPolicy.
type NimbusPolicyBuilder struct {
	Client client.Client
}

// NewNimbusPolicyBuilder creates a new instance of NimbusPolicyBuilder.
func NewNimbusPolicyBuilder(client client.Client) (*NimbusPolicyBuilder, error) {
	return &NimbusPolicyBuilder{
		Client: client,
	}, nil
}

// BuildNimbusPolicy generates a NimbusPolicy based on SecurityIntent and SecurityIntentBinding.
func (builder *NimbusPolicyBuilder) BuildNimbusPolicy(ctx context.Context, client client.Client, req ctrl.Request, bindingInfo *intentbinder.BindingInfo) (*v1.NimbusPolicy, error) {
	log := log.FromContext(ctx)
	log.Info("Start NimbusPolicy Builder")

	// Validates bindingInfo.
	if bindingInfo == nil || len(bindingInfo.IntentNames) == 0 || len(bindingInfo.IntentNamespaces) == 0 ||
		len(bindingInfo.BindingNames) == 0 || len(bindingInfo.BindingNamespaces) == 0 {
		return nil, fmt.Errorf("Invalid bindingInfo: one or more arrays are empty")
	}

	log.Info("Create NimbusPolicy")

	var nimbusRulesList []v1.NimbusRules
	// Iterate over intent names to build rules.
	for i, intentName := range bindingInfo.IntentNames {
		// Checks for array length consistency.
		if i >= len(bindingInfo.IntentNamespaces) || i >= len(bindingInfo.BindingNames) ||
			i >= len(bindingInfo.BindingNamespaces) {
			return nil, fmt.Errorf("Index error: out of range for bindingInfo array.")
		}

		intentNamespace := bindingInfo.IntentNamespaces[i]
		intent, err := fetchIntentByName(ctx, client, intentName, intentNamespace)
		if err != nil {
			return nil, err
		}

		// Checks if arrays in bindingInfo are empty.
		if len(bindingInfo.IntentNames) == 0 || len(bindingInfo.BindingNames) == 0 {
			return nil, fmt.Errorf("Empty error: No intent or binding to be processed")
		}

		var rules []v1.Rule

		// Constructs a rule from the intent parameters.
		rule := v1.Rule{
			RuleAction:        intent.Spec.Intent.Action,
			MatchProtocols:    []v1.MatchProtocol{},
			MatchPaths:        []v1.MatchPath{},
			MatchDirectories:  []v1.MatchDirectory{},
			MatchPatterns:     []v1.MatchPattern{},
			MatchCapabilities: []v1.MatchCapability{},
			MatchSyscalls:     []v1.MatchSyscall{},
			MatchSyscallPaths: []v1.MatchSyscallPath{},
			FromCIDRSet:       []v1.CIDRSet{},
			ToPorts:           []v1.ToPort{},
		}

		for _, param := range intent.Spec.Intent.Params {
			processSecurityIntentParams(&rule, param)
		}
		rules = append(rules, rule)

		nimbusRule := v1.NimbusRules{
			Id:          intent.Spec.Intent.Id,
			Type:        "", // Set Type if necessary
			Description: intent.Spec.Intent.Description,
			Rule:        rules,
		}
		nimbusRulesList = append(nimbusRulesList, nimbusRule)
	}

	// Fetches the binding to extract selector.
	bindingName := bindingInfo.BindingNames[0]
	bindingNamespace := bindingInfo.BindingNamespaces[0]
	binding, err := fetchBindingByName(ctx, client, bindingName, bindingNamespace)
	if err != nil {
		return nil, err
	}

	// Extracts match labels from the binding selector.
	matchLabels, err := extractSelector(ctx, client, binding.Spec.Selector, bindingName, bindingNamespace)
	if err != nil {
		return nil, err
	}

	// Creates a NimbusPolicy.
	nimbusPolicy := &v1.NimbusPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      binding.Name,
			Namespace: binding.Namespace,
		},
		Spec: v1.NimbusPolicySpec{
			Selector: v1.NimbusSelector{
				MatchLabels: matchLabels,
			},
			NimbusRules: nimbusRulesList,
		},
		Status: v1.NimbusPolicyStatus{
			PolicyStatus: "Pending",
		},
	}

	log.Info("Completed creating New NimbusPolicy", "Policy.Name", nimbusPolicy.Name, "Policy.Namespace", nimbusPolicy.Namespace)
	return nimbusPolicy, nil
}

// fetchIntentByName fetches a SecurityIntent by its name and namespace.
func fetchIntentByName(ctx context.Context, client client.Client, name string, namespace string) (*v1.SecurityIntent, error) {
	log := log.FromContext(ctx)

	var intent v1.SecurityIntent
	if err := client.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, &intent); err != nil {
		log.Error(err, "Failed to get SecurityIntent")
		return nil, err
	}
	return &intent, nil
}

// fetchBindingByName fetches a SecurityIntentBinding by its name and namespace.
func fetchBindingByName(ctx context.Context, client client.Client, name string, namespace string) (*v1.SecurityIntentBinding, error) {
	log := log.FromContext(ctx)
	var binding v1.SecurityIntentBinding
	if err := client.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, &binding); err != nil {
		log.Error(err, "Failed to get SecurityIntentBinding")
		return nil, err
	}
	return &binding, nil
}

// processSecurityIntentParams processes the parameters of a SecurityIntent.
func processSecurityIntentParams(rule *v1.Rule, param v1.SecurityIntentParams) {
	// Processes MatchProtocols.
	for _, mp := range param.MatchProtocols {
		rule.MatchProtocols = append(rule.MatchProtocols, v1.MatchProtocol(mp))

	}

	// Processes MatchPaths.
	for _, mp := range param.MatchPaths {
		rule.MatchPaths = append(rule.MatchPaths, v1.MatchPath(mp))
	}

	// Processes MatchDirectories.
	for _, md := range param.MatchDirectories {
		rule.MatchDirectories = append(rule.MatchDirectories, v1.MatchDirectory{
			Directory:  md.Directory,
			FromSource: []v1.NimbusFromSource{},
		})
	}

	// Processes MatchPatterns.
	for _, mp := range param.MatchPatterns {
		rule.MatchPatterns = append(rule.MatchPatterns, v1.MatchPattern(mp))
	}

	// Processes MatchCapabilities.
	for _, mc := range param.MatchCapabilities {
		matchCapability := v1.MatchCapability{
			Capability: mc.Capability,
			FromSource: []v1.NimbusFromSource{},
		}
		rule.MatchCapabilities = append(rule.MatchCapabilities, matchCapability)
	}

	// Processes MatchSyscalls and MatchSyscallPaths.
	for _, ms := range param.MatchSyscalls {
		var matchSyscall v1.MatchSyscall
		matchSyscall.Syscalls = ms.Syscalls
		rule.MatchSyscalls = append(rule.MatchSyscalls, matchSyscall)
	}

	for _, msp := range param.MatchSyscallPaths {
		rule.MatchSyscallPaths = append(rule.MatchSyscallPaths, v1.MatchSyscallPath(msp))
	}

	// Processes FromCIDRSet.
	for _, fcs := range param.FromCIDRSet {
		rule.FromCIDRSet = append(rule.FromCIDRSet, v1.CIDRSet(fcs))
	}

	// Processes ToPorts.
	for _, tp := range param.ToPorts {
		var ports []v1.Port
		for _, p := range tp.Ports {
			ports = append(ports, v1.Port(p))
		}
		rule.ToPorts = append(rule.ToPorts, v1.ToPort{
			Ports: ports,
		})
	}
}

// extractSelector extracts match labels from a Selector.
func extractSelector(ctx context.Context, client client.Client, selector v1.Selector, name string, namespace string) (map[string]string, error) {
	matchLabels := make(map[string]string) // Initialize map for match labels.

	// Process CEL expressions.
	if len(selector.CEL) > 0 {
		celMatchLabels, err := ProcessCEL(ctx, client, namespace, selector.CEL)
		if err != nil {
			return nil, fmt.Errorf("Error processing CEL: %v", err)
		}
		for k, v := range celMatchLabels {
			// Remove the "labels["" and "]" parts from the key
			k = strings.TrimPrefix(k, `labels["`)
			k = strings.TrimSuffix(k, `"]`)
			matchLabels[k] = v
		}
	}

	// Process Any/All fields.
	if len(selector.Any) > 0 || len(selector.All) > 0 {
		matchLabelsFromAnyAll, err := ProcessMatchLabels(selector.Any, selector.All)
		if err != nil {
			return nil, fmt.Errorf("Error processing Any/All match labels: %v", err)
		}
		for key, value := range matchLabelsFromAnyAll {
			matchLabels[key] = value
		}
	}

	return matchLabels, nil
}

// ProcessCEL processes CEL expressions to generate matchLabels.
func ProcessCEL(ctx context.Context, k8sClient client.Client, namespace string, expressions []string) (map[string]string, error) {
	log := log.FromContext(ctx)
	log.Info("Processing CEL expressions", "Namespace", namespace)

	env, err := cel.NewEnv(
		cel.Declarations(
			decls.NewVar("labels", decls.NewMapType(decls.String, decls.String)), // Declare 'labels' variable
		),
	)
	if err != nil {
		return nil, fmt.Errorf("Error creating CEL environment: %v", err)
	}

	matchLabels := make(map[string]string)

	// Retrieve pod list
	var podList corev1.PodList
	if err := k8sClient.List(ctx, &podList, client.InNamespace(namespace)); err != nil {
		log.Error(err, "Error listing pods in namespace", "Namespace", namespace)
		return nil, fmt.Errorf("Error listing pods: %v", err)
	}

	// Initialize an empty map to store label expressions
	labelExpressions := make(map[string]bool)

	// Parse and evaluate label expressions
	for _, expr := range expressions {
		ast, issues := env.Compile(expr)
		if issues != nil && issues.Err() != nil {
			return nil, fmt.Errorf("Error compiling CEL expression: %v", issues.Err())
		}

		prg, err := env.Program(ast)
		if err != nil {
			return nil, fmt.Errorf("Error creating CEL program: %v", err)
		}

		// Evaluate CEL expression for each pod
		for _, pod := range podList.Items {
			resource := map[string]interface{}{
				"labels": pod.Labels,
			}

			out, _, err := prg.Eval(map[string]interface{}{
				"labels": resource["labels"],
			})
			if err != nil {
				return nil, fmt.Errorf("Error evaluating CEL expression: %v", err)
			}

			if outValue, ok := out.Value().(bool); ok && outValue {
				// Mark this expression as true for at least one pod
				labelExpressions[expr] = true
			}
		}
	}

	// Extract labels based on true label expressions
	for expr, isTrue := range labelExpressions {
		if isTrue {
			// Extract labels from the expression and add them to matchLabels
			labels := extractLabelsFromExpression(expr)
			for k, v := range labels {
				matchLabels[k] = v
			}
		}
	}

	return matchLabels, nil
}

// Extracts labels from a CEL expression
func extractLabelsFromExpression(expr string) map[string]string {
	// This is a simplified example, you can implement a more robust label extraction logic here
	labels := make(map[string]string)

	// Split the expression by '==' and extract labels
	parts := strings.Split(expr, "==")
	if len(parts) == 2 {
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		// Remove quotes from value if present
		value = strings.Trim(value, "\"'")

		// Add the extracted label to the map
		labels[key] = value
	}

	return labels
}

// ProcessMatchLabels processes any/all fields to generate matchLabels.
func ProcessMatchLabels(any, all []v1.ResourceFilter) (map[string]string, error) {
	matchLabels := make(map[string]string)

	// Process logic for Any field.
	for _, filter := range any {
		for key, value := range filter.Resources.MatchLabels {
			matchLabels[key] = value
		}
	}

	// Process logic for All field.
	for _, filter := range all {
		for key, value := range filter.Resources.MatchLabels {
			matchLabels[key] = value
		}
	}

	return matchLabels, nil
}
