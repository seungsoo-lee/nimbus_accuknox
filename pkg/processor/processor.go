package processor

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	v1 "github.com/5GSEC/nimbus/api/v1"
	applier "github.com/5GSEC/nimbus/pkg/exporter/applier"
	"github.com/5GSEC/nimbus/pkg/processor/intentbinder"
	"github.com/5GSEC/nimbus/pkg/processor/nimbuspolicybuilder"
)

// PolicyProcessor is responsible for processing SecurityIntent and SecurityIntentBinding and applying NimbusPolicy.
type PolicyProcessor struct {
	Client              client.Client
	Scheme              *runtime.Scheme
	IntentBinder        *intentbinder.IntentBinder
	NimbusPolicyBuilder *nimbuspolicybuilder.NimbusPolicyBuilder
	NimbusPolicyApplier *applier.NimbusPolicyApplier
}

// NewPolicyProcessor creates a new instance of PolicyProcessor.
func NewPolicyProcessor(client client.Client, scheme *runtime.Scheme) (*PolicyProcessor, error) {
	if client == nil {
		return nil, fmt.Errorf("PolicyProcessor: Client is nil")
	}

	IntentBinder, err := intentbinder.NewIntentBinder(client)
	if err != nil {
		return nil, fmt.Errorf("PolicyProcessor: Failed to initialize WatcherController: %v", err)
	}

	NimbusPolicyBuilder, err := nimbuspolicybuilder.NewNimbusPolicyBuilder(client)
	if err != nil {
		return nil, fmt.Errorf("PolicyProcessor: Failed to initialize PolicyProcessor: %v", err)
	}

	NimbusPolicyApplier, err := applier.NewNimbusPolicyApplier(client, scheme)
	if err != nil {
		return nil, fmt.Errorf("PolicyProcessor: Failed to initialize PolicyProcessor: %v", err)
	}

	return &PolicyProcessor{
		Client:              client,
		Scheme:              scheme,
		IntentBinder:        IntentBinder,
		NimbusPolicyBuilder: NimbusPolicyBuilder,
		NimbusPolicyApplier: NimbusPolicyApplier,
	}, nil
}

// Processor handles the processing of SecurityIntent and SecurityIntentBinding and applies the resulting NimbusPolicy.
func (pp *PolicyProcessor) Processor(ctx context.Context, req ctrl.Request, binding *v1.SecurityIntentBinding) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	if pp == nil {
		return ctrl.Result{}, fmt.Errorf("Processor is nil")
	}
	log.Info("Start Processor")

	// Match and bind intents to create binding information
	bindingInfo, err := pp.IntentBinder.IntentBinder(ctx, pp.Client, req, binding)
	if err != nil {
		log.Error(err, "Failed to match intents")
		return ctrl.Result{}, err
	}

	nimbusPolicy, err := pp.NimbusPolicyBuilder.BuildNimbusPolicy(ctx, pp.Client, req, bindingInfo)
	if err != nil {
		log.Error(err, "Failed to build NimbusPolicy")
		return ctrl.Result{}, err
	}

	_, err = pp.NimbusPolicyApplier.Applier(ctx, req, nimbusPolicy)
	if err != nil {
		log.Error(err, "Failed to apply NimbusPolicy")
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, err
}
