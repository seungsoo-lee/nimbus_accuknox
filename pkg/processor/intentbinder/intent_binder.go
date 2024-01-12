// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Nimbus

package intentbinder

import (
	"context"

	v1 "github.com/5GSEC/nimbus/api/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// IntentBinder is responsible for binding SecurityIntents and SecurityIntentBindings.
type IntentBinder struct {
	Client client.Client
}

// NewIntentBinder creates a new instance of IntentBinder.
func NewIntentBinder(client client.Client) (*IntentBinder, error) {
	return &IntentBinder{
		Client: client,
	}, nil
}

// BindingInfo holds the information about the binding between SecurityIntent and SecurityIntentBinding.
type BindingInfo struct {
	IntentNames       []string
	IntentNamespaces  []string
	BindingNames      []string
	BindingNamespaces []string
}

func (ib *IntentBinder) IntentBinder(ctx context.Context, client client.Client, req ctrl.Request, bindings *v1.SecurityIntentBinding) (*BindingInfo, error) {
	log := log.FromContext(ctx)
	log.Info("Start Intent Binder")

	intents, err := FindMatchingSecurityIntents(ctx, client, bindings)
	if err != nil {
		return nil, err
	}

	return CreateBindingInfo(ctx, intents, bindings), nil
}

func FindMatchingSecurityIntents(ctx context.Context, client client.Client, bindings *v1.SecurityIntentBinding) ([]*v1.SecurityIntent, error) {
	log := log.FromContext(ctx)

	if bindings == nil {
		log.Info("No bindings available for processing")
		return nil, nil
	}
	log.Info("Looking for matching security intents", "BindingName", bindings.Name, "Namespace", bindings.Namespace)

	var intents []*v1.SecurityIntent
	for _, intentRef := range bindings.Spec.Intents {
		intent := &v1.SecurityIntent{}
		err := client.Get(ctx, types.NamespacedName{Name: intentRef.Name, Namespace: bindings.Namespace}, intent)
		if err == nil {
			intents = append(intents, intent)
		}
	}

	return intents, nil
}

func CreateBindingInfo(ctx context.Context, intents []*v1.SecurityIntent, binding *v1.SecurityIntentBinding) *BindingInfo {
	log := log.FromContext(ctx)

	bindingInfo := &BindingInfo{
		// Initialize slices
		IntentNames:       []string{},
		IntentNamespaces:  []string{},
		BindingNames:      []string{},
		BindingNamespaces: []string{},
	}

	log.Info("Saving binding information", "BindingName", binding.Name, "Namespace", binding.Namespace)

	for _, intent := range intents {
		// Add binding information
		bindingInfo.IntentNames = append(bindingInfo.IntentNames, intent.Name)
		bindingInfo.IntentNamespaces = append(bindingInfo.IntentNamespaces, intent.Namespace)
	}
	// Add current binding information
	bindingInfo.BindingNames = append(bindingInfo.BindingNames, binding.Name)
	bindingInfo.BindingNamespaces = append(bindingInfo.BindingNamespaces, binding.Namespace)

	return bindingInfo
}
