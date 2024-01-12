// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Nimbus

package applier

import (
	"context"

	"sigs.k8s.io/controller-runtime/pkg/log"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	ksp "github.com/kubearmor/KubeArmor/pkg/KubeArmorController/api/security.kubearmor.com/v1"
)

// Applier manages the enforcement of policies.
type Applier struct {
	Client client.Client
}

// NewApplier creates a new Applier.
func NewApplier(client client.Client) *Applier {
	return &Applier{Client: client}
}

// ApplyPolicy applies or updates a given KubeArmorPolicy.
func (e *Applier) ApplyPolicy(ctx context.Context, kubeArmorPolicy *ksp.KubeArmorPolicy) error {
	log := log.FromContext(ctx)

	// Check if the policy already exists
	existingPolicy := &ksp.KubeArmorPolicy{}
	err := e.Client.Get(ctx, types.NamespacedName{Name: kubeArmorPolicy.Name, Namespace: kubeArmorPolicy.Namespace}, existingPolicy)
	if err != nil && !errors.IsNotFound(err) {
		log.Error(err, "Existing KubeArmorPolicy lookup failed", "PolicyName", kubeArmorPolicy.Name)
		return err
	}

	// Update if exists, create otherwise
	if errors.IsNotFound(err) {
		log.Info("Apply a new KubeArmorPolicy", "PolicyName", kubeArmorPolicy.Name, "Policy", kubeArmorPolicy)
		return e.Client.Create(ctx, kubeArmorPolicy)
	} else {
		log.Info("Update existing KubeArmorPolicy", "PolicyName", kubeArmorPolicy.Name)
		existingPolicy.Spec = kubeArmorPolicy.Spec
		return e.Client.Update(ctx, existingPolicy)
	}
}