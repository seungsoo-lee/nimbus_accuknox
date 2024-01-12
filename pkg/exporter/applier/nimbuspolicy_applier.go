// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Nimbus

package applier

import (
	"context"
	"time"

	v1 "github.com/5GSEC/nimbus/api/v1"
	"github.com/5GSEC/nimbus/pkg/exporter/nimbuspolicy"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// NimbusPolicyApplier is responsible for applying NimbusPolicy objects to the Kubernetes cluster.
type NimbusPolicyApplier struct {
	Client       client.Client
	Scheme       *runtime.Scheme
	NimbusPolicy *nimbuspolicy.NimbusPolicyReconciler
}

// NewNimbusPolicyApplier creates a new instance of NimbusPolicyApplier.
func NewNimbusPolicyApplier(client client.Client, scheme *runtime.Scheme) (*NimbusPolicyApplier, error) {
	return &NimbusPolicyApplier{
		Client:       client,
		Scheme:       scheme,
		NimbusPolicy: nimbuspolicy.NewNimbusPolicyReconciler(client, scheme),
	}, nil
}

func (npa *NimbusPolicyApplier) Applier(ctx context.Context, req ctrl.Request, policy *v1.NimbusPolicy) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	existingPolicy := &v1.NimbusPolicy{}
	err := npa.Client.Get(ctx, client.ObjectKeyFromObject(policy), existingPolicy)

	if err != nil && !errors.IsNotFound(err) {
		log.Error(err, "Failed to get NimbusPolicy", "Policy", policy.Name)
		return ctrl.Result{}, err
	}

	if errors.IsNotFound(err) {
		// If NimbusPolicy already exists, update it.
		log.Info("Applying new NimbusPolicy", "Policy", policy.Name)
		if err := npa.Client.Create(ctx, policy); err != nil {
			log.Error(err, "Failed to apply NimbusPolicy", "Policy", policy.Name)
			return ctrl.Result{}, err
		}
	} else {
		// If NimbusPolicy already exists, update it.
		log.Info("Updating existing NimbusPolicy", "Policy", policy.Name)
		policy.ResourceVersion = existingPolicy.ResourceVersion
		if err := npa.Client.Update(ctx, policy); err != nil {
			log.Error(err, "Failed to update NimbusPolicy", "Policy", policy.Name)
			return ctrl.Result{}, err
		}
	}

	time.Sleep(time.Second * 5)

	_, err = npa.NimbusPolicy.Reconcile(ctx, req)
	if err != nil {
		log.Error(err, "Failed to reconcile NimbusPolicy", "Policy", policy.Name)
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}
