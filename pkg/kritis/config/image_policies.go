//
// Copyright 2022 The Sigstore Authors.
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

package config

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/grafeas/kritis/pkg/kritis/apis/kritis/v1beta1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/yaml"
)

const (
	// ImagePoliciesConfigName is the name of ConfigMap created by the
	// reconciler and consumed by the admission webhook.
	ImagePoliciesConfigName = "config-image-policies"
)

type ImagePolicyConfig struct {
	// This is the list of ImagePolicies that a admission controller uses
	// to make policy decisions.
	Policies map[string]ClusterImagePolicy
}

// ClusterImagePolicy defines the images that go through verification
// and the authorities used for verification.
// This is the internal representation of the external v1alpha1.ClusterImagePolicy.
// KeyRef does not store secretRefs in internal representation.
// KeyRef does store parsed publicKeys from Data in internal representation.
type ClusterImagePolicy struct {
	AttestationPolicy    []v1beta1.GenericAttestationPolicy `json:"attestation_policy"`
	AttestationAuthority []v1beta1.AttestationAuthority     `json:"attestation_authority"`
}

// NewImagePoliciesConfigFromMap creates an ImagePolicyConfig from the supplied
// Map
func NewImagePoliciesConfigFromMap(data map[string]string) (*ImagePolicyConfig, error) {
	ret := &ImagePolicyConfig{Policies: make(map[string]ClusterImagePolicy, len(data))}
	// Spin through the ConfigMap. Each key will point to resolved
	// ImagePatterns.
	for k, v := range data {
		// This is the example that we use to document / test the ConfigMap.
		if k == "_example" {
			continue
		}
		if v == "" {
			return nil, fmt.Errorf("configmap has an entry %q but no value", k)
		}
		clusterImagePolicy := &ClusterImagePolicy{}

		if err := parseEntry(v, clusterImagePolicy); err != nil {
			return nil, fmt.Errorf("failed to parse the entry %q : %q : %w", k, v, err)
		}
		ret.Policies[k] = *clusterImagePolicy
	}
	return ret, nil
}

// NewImagePoliciesConfigFromConfigMap creates a Features from the supplied ConfigMap
func NewImagePoliciesConfigFromConfigMap(config *corev1.ConfigMap) (*ImagePolicyConfig, error) {
	return NewImagePoliciesConfigFromMap(config.Data)
}

func parseEntry(entry string, out interface{}) error {
	j, err := yaml.YAMLToJSON([]byte(entry))
	if err != nil {
		return fmt.Errorf("config's value could not be converted to JSON: %w : %s", err, entry)
	}
	return json.Unmarshal(j, &out)
}

// GetMatchingPolicies returns all matching Policies and their Authorities that
// need to be matched for the given Image.
// Returned map contains the name of the CIP as the key, and a normalized
// ClusterImagePolicy for it.
func (p *ImagePolicyConfig) GetMatchingPolicies(image string) (map[string]ClusterImagePolicy, error) {
	if p == nil {
		return nil, errors.New("config is nil")
	}

	var lastError error
	ret := make(map[string]ClusterImagePolicy)

	// TODO(vaikas): this is very inefficient, we should have a better
	// way to go from image to Authorities, but just seeing if this is even
	// workable so fine for now.
	for k, v := range p.Policies {
		for _, gap := range v.AttestationPolicy {
			for _, pattern := range gap.Spec.AdmissionAllowlistPatterns {
				if pattern.NamePattern != "" {
					if matched, err := GlobMatch(pattern.NamePattern, image); err != nil {
						lastError = err
					} else if matched {
						ret[k] = v
					}
				}
			}
		}
	}
	return ret, lastError
}
