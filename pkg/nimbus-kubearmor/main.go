// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Nimbus

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	v1 "github.com/5GSEC/nimbus/api/v1"
	"github.com/5GSEC/nimbus/pkg/nimbus-kubearmor/processor/enforcer"
	watcher "github.com/5GSEC/nimbus/pkg/nimbus-kubearmor/receiver/nimbuspolicywatcher"
	"github.com/5GSEC/nimbus/pkg/nimbus-kubearmor/receiver/verifier"
	ctrl "sigs.k8s.io/controller-runtime"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	ksp "github.com/kubearmor/KubeArmor/pkg/KubeArmorController/api/security.kubearmor.com/v1"
)

// Initialize the global scheme variable
var scheme = runtime.NewScheme()

func init() {
	utilruntime.Must(v1.AddToScheme(scheme))
	utilruntime.Must(ksp.AddToScheme(scheme))
}

func main() {
	ctrl.SetLogger(zap.New(zap.UseDevMode(true)))
	log := ctrl.Log.WithName("main")

	log.Info("Starting Kubernetes client configuration")

	var cfg *rest.Config
	var err error
	if cfg, err = rest.InClusterConfig(); err != nil {
		kubeconfig := filepath.Join(os.Getenv("HOME"), ".kube", "config")
		cfg, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			log.Error(err, "Failed to set up Kubernetes config")
		}
	}

	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		log.Error(err, "Failed to create client")
	}

	log.Info("Booting up the Nimbus Policy Watcher")
	npw := watcher.NewNimbusPolicyWatcher(c)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	policyChan, err := npw.WatchNimbusPolicies(ctx)
	if err != nil {
		log.Error(err, "NimbusPolicy: Watch Failed")
	}

	detectedPolicies := make(map[string]bool)
	enforcer := enforcer.NewPolicyEnforcer(c)

	log.Info("Booting up the Kubearmor Policy Processor")
	for {
		select {
		case policy := <-policyChan:
			policyKey := fmt.Sprintf("%s/%s", policy.Namespace, policy.Name)
			if _, detected := detectedPolicies[policyKey]; !detected {
				if verifier.HandlePolicy(policy) {
					log.Info("Detected NimbusPolicy: Name: %s, Namespace: %s, ID: %s \n%+v\n", policy.Namespace, policy.Name, getRulesIDs(policy), policy)
					detectedPolicies[policyKey] = true

					err := enforcer.Enforcer(ctx, policy)
					if err != nil {
						log.Error(err, "Error exporting NimbusPolicy")
					} else {
						log.Info("Completed exporting the Nimbus policy to a KubeArmor policy.")
					}
				}
			}
		case <-time.After(120 * time.Second):
			log.Info("NimbusPolicy: No detections for 120 seconds")
		}
	}
}

func getRulesIDs(policy v1.NimbusPolicy) string {
	var ruleIDs []string
	for _, rule := range policy.Spec.NimbusRules {
		ruleIDs = append(ruleIDs, rule.Id)
	}
	return fmt.Sprintf("[%s]", strings.Join(ruleIDs, ", "))
}
