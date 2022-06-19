//
// Copyright 2021 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package review

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/google/go-containerregistry/pkg/authn/k8schain"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/grafeas/kritis/pkg/kritis/config"
	corev1 "k8s.io/api/core/v1"
	"knative.dev/pkg/logging"
	"knative.dev/pkg/system"

	"k8s.io/client-go/kubernetes"
	listersv1 "k8s.io/client-go/listers/core/v1"
	"knative.dev/pkg/apis"
	duckv1 "knative.dev/pkg/apis/duck/v1"
	kubeclient "knative.dev/pkg/client/injection/kube/client"
	secretinformer "knative.dev/pkg/injection/clients/namespacedkube/informers/core/v1/secret"
)

type Validator struct {
	client     kubernetes.Interface
	lister     listersv1.SecretLister
	secretName string
}

func NewValidator(ctx context.Context, secretName string) *Validator {
	return &Validator{
		client:     kubeclient.Get(ctx),
		lister:     secretinformer.Get(ctx).Lister(),
		secretName: secretName,
	}
}

// ValidatePodSpecable implements duckv1.PodSpecValidator
func (v *Validator) ValidatePodSpecable(ctx context.Context, wp *duckv1.WithPod) *apis.FieldError {
	if wp.DeletionTimestamp != nil {
		// Don't block things that are being deleted.
		return nil
	}

	imagePullSecrets := make([]string, 0, len(wp.Spec.Template.Spec.ImagePullSecrets))
	for _, s := range wp.Spec.Template.Spec.ImagePullSecrets {
		imagePullSecrets = append(imagePullSecrets, s.Name)
	}

	return nil
}

// ValidatePod implements duckv1.PodValidator
func (v *Validator) ValidatePod(ctx context.Context, p *duckv1.Pod) *apis.FieldError {
	if p.DeletionTimestamp != nil {
		// Don't block things that are being deleted.
		return nil
	}
	imagePullSecrets := make([]string, 0, len(p.Spec.ImagePullSecrets))
	for _, s := range p.Spec.ImagePullSecrets {
		imagePullSecrets = append(imagePullSecrets, s.Name)
	}
	return nil
}

// ValidateCronJob implements duckv1.CronJobValidator
func (v *Validator) ValidateCronJob(ctx context.Context, c *duckv1.CronJob) *apis.FieldError {
	if c.DeletionTimestamp != nil {
		// Don't block things that are being deleted.
		return nil
	}
	imagePullSecrets := make([]string, 0, len(c.Spec.JobTemplate.Spec.Template.Spec.ImagePullSecrets))
	for _, s := range c.Spec.JobTemplate.Spec.Template.Spec.ImagePullSecrets {
		imagePullSecrets = append(imagePullSecrets, s.Name)
	}

	return nil
}

func (v *Validator) validatePodSpec(ctx context.Context, namespace string, ps *corev1.PodSpec, opt k8schain.Options) (errs *apis.FieldError) {
	kc, err := k8schain.New(ctx, v.client, opt)
	if err != nil {
		logging.FromContext(ctx).Warnf("Unable to build k8schain: %v", err)
		return apis.ErrGeneric(err.Error(), apis.CurrentField)
	}

	s, err := v.lister.Secrets(system.Namespace()).Get(v.secretName)
	if err != nil {
		return apis.ErrGeneric(err.Error(), apis.CurrentField)
	}

	keys, kerr := getKeys(ctx, s.Data)
	if kerr != nil {
		return kerr
	}

	checkContainers := func(cs []corev1.Container, field string) {
		for i, c := range cs {
			ref, err := name.ParseReference(c.Image)
			if err != nil {
				errs = errs.Also(apis.ErrGeneric(err.Error(), "image").ViaFieldIndex(field, i))
				continue
			}

			// Require digests, otherwise the validation is meaningless
			// since the tag can move.
			if _, ok := ref.(name.Digest); !ok {
				errs = errs.Also(apis.ErrInvalidValue(
					fmt.Sprintf("%s must be an image digest", c.Image),
					"image",
				).ViaFieldIndex(field, i))
				continue
			}

			containerKeys := keys
			config := config.FromContext(ctx)

			// During the migration from the secret only validation into policy
			// based ones. If there were matching policies that successfully
			// validated the image, keep tally of it and if all Policies that
			// matched validated, skip the traditional one since they are not
			// necessarily going to play nicely together.
			passedPolicyChecks := false
			if config != nil {
				policies, err := config.ImagePolicyConfig.GetMatchingPolicies(ref.Name())
				if err != nil {
					errorField := apis.ErrGeneric(err.Error(), "image").ViaFieldIndex(field, i)
					errorField.Details = c.Image
					errs = errs.Also(errorField)
					continue
				}

				// If there is at least one policy that matches, that means it
				// has to be satisfied.
				if len(policies) > 0 {
					signatures, fieldErrors := validatePolicies(ctx, namespace, ref, policies, ociremote.WithRemoteOptions(remote.WithAuthFromKeychain(kc)))

					if len(signatures) != len(policies) {
						logging.FromContext(ctx).Warnf("Failed to validate at least one policy for %s", ref.Name())
						// Do we really want to add all the error details here?
						// Seems like we can just say which policy failed, so
						// doing that for now.
						for failingPolicy, policyErrs := range fieldErrors {
							errorField := apis.ErrGeneric(fmt.Sprintf("failed policy: %s", failingPolicy), "image").ViaFieldIndex(field, i)
							errDetails := c.Image
							for _, policyErr := range policyErrs {
								errDetails = errDetails + " " + policyErr.Error()
							}
							errorField.Details = errDetails
							errs = errs.Also(errorField)
						}
						// Because there was at least one policy that was
						// supposed to be validated, but it failed, then fail
						// this image. It should not fall through to the
						// traditional secret checking so it does not slip
						// through the policy cracks, and also to reduce noise
						// in the errors returned to the user.
						continue
					} else {
						logging.FromContext(ctx).Warnf("Validated authorities for %s", ref.Name())
						// Only say we passed (aka, we skip the traditidional check
						// below) if more than one authority was validated, which
						// means that there was a matching ClusterImagePolicy.
						if len(signatures) > 0 {
							passedPolicyChecks = true
						}
					}
				}
				logging.FromContext(ctx).Errorf("policies: for %v", policies)
			}

			if passedPolicyChecks {
				logging.FromContext(ctx).Debugf("Found at least one matching policy and it was validated for %s", ref.Name())
				continue
			}
			logging.FromContext(ctx).Errorf("ref: for %v", ref)
			logging.FromContext(ctx).Errorf("container Keys: for %v", containerKeys)

			if _, err := valid(ctx, ref, nil, containerKeys, ociremote.WithRemoteOptions(remote.WithAuthFromKeychain(kc))); err != nil {
				errorField := apis.ErrGeneric(err.Error(), "image").ViaFieldIndex(field, i)
				errorField.Details = c.Image
				errs = errs.Also(errorField)
				continue
			}
		}
	}

	checkContainers(ps.InitContainers, "initContainers")
	checkContainers(ps.Containers, "containers")

	return errs
}

func getKeys(ctx context.Context, cfg map[string][]byte) ([]crypto.PublicKey, *apis.FieldError) {
	keys := []crypto.PublicKey{}
	errs := []error{}

	logging.FromContext(ctx).Debugf("Got public key: %v", cfg["cosign.pub"])

	pems := parsePems(cfg["cosign.pub"])
	for _, p := range pems {
		// TODO: (@dlorenc) check header
		key, err := x509.ParsePKIXPublicKey(p.Bytes)
		if err != nil {
			errs = append(errs, err)
		} else {
			keys = append(keys, key.(crypto.PublicKey))
		}
	}
	if keys == nil {
		return nil, apis.ErrGeneric(fmt.Sprintf("malformed cosign.pub: %v", errs), apis.CurrentField)
	}
	return keys, nil
}

func parsePems(b []byte) []*pem.Block {
	p, rest := pem.Decode(b)
	if p == nil {
		return nil
	}
	pems := []*pem.Block{p}

	if rest != nil {
		return append(pems, parsePems(rest)...)
	}
	return pems
}
