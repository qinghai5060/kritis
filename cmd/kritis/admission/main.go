/*
Copyright 2018 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"github.com/golang/glog"
	"github.com/grafeas/kritis/pkg/kritis/config"
	"github.com/grafeas/kritis/pkg/kritis/review"
	"github.com/pkg/errors"
	"net/http"
	_ "net/http/pprof"
	"time"

	kubernetesutil "github.com/grafeas/kritis/pkg/kritis/kubernetes"
	"github.com/grafeas/kritis/pkg/kritis/metadata/grafeas"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	batchv1beta1 "k8s.io/api/batch/v1beta1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	duckv1 "knative.dev/pkg/apis/duck/v1"
	"knative.dev/pkg/configmap"
	"knative.dev/pkg/controller"
	"knative.dev/pkg/injection/sharedmain"
	"knative.dev/pkg/logging"
	"knative.dev/pkg/signals"
	"knative.dev/pkg/webhook"
	"knative.dev/pkg/webhook/certificates"
	"knative.dev/pkg/webhook/resourcesemantics"
	"knative.dev/pkg/webhook/resourcesemantics/validation"

	"github.com/grafeas/kritis/cmd/kritis/version"
	"github.com/grafeas/kritis/pkg/kritis/admission"
	"github.com/grafeas/kritis/pkg/kritis/constants"
	"github.com/grafeas/kritis/pkg/kritis/crd/kritisconfig"
	"github.com/grafeas/kritis/pkg/kritis/cron"
)

const (
	// Default values for the configuration
	DefaultMetadataBackend = constants.ContainerAnalysisMetadata
	DefaultCronInterval    = "1h"
	DefaultServerAddr      = ":443"
)

var (
	tlsCertFile  string
	tlsKeyFile   string
	grafeasCerts string
	showVersion  bool
	runCron      bool
	webhookName  string
	secretName   string
)

func main() {
	flag.StringVar(&tlsCertFile, "tls-cert-file", "/var/tls/tls.crt", "TLS certificate file.")
	flag.StringVar(&tlsKeyFile, "tls-key-file", "/var/tls/tls.key", "TLS key file.")
	flag.StringVar(&grafeasCerts, "grafeas-certs", "/etc/config/grafeascerts.yaml", "Grafeas certificates.")
	flag.BoolVar(&showVersion, "version", false, "kritis-server version")
	flag.BoolVar(&runCron, "run-cron", false, "Run cron job in foreground.")
	flag.StringVar(&webhookName, "webhook-name", "policy.sigstore.dev", "The name of the validating and mutating webhook configurations as well as the webhook name that is automatically configured, if exists, with different rules and client settings setting how the admission requests to be dispatched to policy-controller.")
	flag.StringVar(&secretName, "secret-name", "", "The name of the secret in the webhook's namespace that holds the public key for verification.")

	flag.Parse()
	if err := flag.Set("logtostderr", "true"); err != nil {
		glog.Fatal(errors.Wrap(err, "unable to set logtostderr"))
	}

	if showVersion {
		fmt.Println(version.Commit)
		return
	}

	opts := webhook.Options{
		ServiceName: "webhook",
		Port:        443,
		SecretName:  "webhook-certs",
	}
	ctx := webhook.WithOptions(signals.NewContext(), opts)

	// Allow folks to configure the port the webhook serves on.
	flag.IntVar(&opts.Port, "secure-port", opts.Port, "The port on which to serve HTTPS.")

	sharedmain.MainWithContext(ctx, "policy-controller",
		certificates.NewController,
	)
	// KritisConfig is a cluster-wide CRD.
	kritisConfigs, err := kritisconfig.KritisConfigs()
	if err != nil {
		errMsg := fmt.Sprintf("error getting kritis config: %v", err)
		glog.Errorf(errMsg)
		return
	}

	// Set the defaults that will be used if no KritisConfig is defined
	metadataBackend := DefaultMetadataBackend
	cronInterval := DefaultCronInterval
	serverAddr := DefaultServerAddr

	config := &admission.Config{
		Metadata: metadataBackend,
	}

	if len(kritisConfigs) == 0 {
		glog.Infof("No KritisConfigs found in any namespace, will assume the defaults")
	} else if len(kritisConfigs) > 1 {
		glog.Errorf("More than 1 KritisConfig found, expected to have only 1 in the cluster")
		return
	} else {
		kritisConf := kritisConfigs[0]
		// TODO(https://github.com/grafeas/kritis/issues/304): Use CRD validation instead
		if kritisConf.Spec.MetadataBackend != "" {
			config.Metadata = kritisConf.Spec.MetadataBackend
		}
		if kritisConf.Spec.CronInterval != "" {
			cronInterval = kritisConf.Spec.CronInterval
		}
		if kritisConf.Spec.ServerAddr != "" {
			serverAddr = kritisConf.Spec.ServerAddr
		}
		if config.Metadata == constants.GrafeasMetadata {
			config.Grafeas = kritisConf.Spec.Grafeas
			if err := grafeas.ValidateConfig(config.Grafeas); err != nil {
				glog.Fatal(err)
			}
			certs, err := grafeas.LoadConfig(grafeasCerts)
			if err != nil {
				glog.Fatal(err)
			}
			config.Certs = certs
		}
	}
	// TODO: (tejaldesai) This is getting complicated. Use CLI Library.
	if runCron {
		cronConfig, err := getCronConfig(config)
		if err != nil {
			glog.Fatalf("Could not run cron job in foreground: %s", err)
		}
		if err := cron.RunInForeground(*cronConfig); err != nil {
			glog.Fatalf("Error Checking pods: %s", err)
		}
		return
	}

	// Kick off background cron job.
	if err := StartCronJob(config, cronInterval); err != nil {
		glog.Fatal(errors.Wrap(err, "starting background job"))
	}

	// Start the Kritis Server.
	glog.Infof("Running the server, address: %s", serverAddr)
	http.HandleFunc("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		admission.ReviewHandler(w, r, config)
	}))
	httpsServer := NewServer(serverAddr)
	glog.Fatal(httpsServer.ListenAndServeTLS(tlsCertFile, tlsKeyFile))
}

func NewServer(addr string) *http.Server {
	return &http.Server{
		Addr: addr,
		TLSConfig: &tls.Config{
			// TODO: Change this to tls.RequireAndVerifyClientCert
			ClientAuth: tls.NoClientCert,
		},
	}
}

// StartCron starts the cron.StartCronJob in background.
func StartCronJob(config *admission.Config, cronInterval string) error {
	d, err := time.ParseDuration(cronInterval)
	if err != nil {
		return err
	}
	cronConfig, err := getCronConfig(config)
	if err != nil {
		return err
	}
	go cron.Start(context.Background(), *cronConfig, d)
	return nil
}

func getCronConfig(config *admission.Config) (*cron.Config, error) {
	ki, err := kubernetesutil.GetClientset()
	if err != nil {
		return nil, err
	}
	kcs := ki.(*kubernetes.Clientset)
	client, err := admission.MetadataClient(config)
	if err != nil {
		return nil, err
	}
	return cron.NewCronConfig(kcs, client), nil
}

var types = map[schema.GroupVersionKind]resourcesemantics.GenericCRD{
	corev1.SchemeGroupVersion.WithKind("Pod"): &duckv1.Pod{},

	appsv1.SchemeGroupVersion.WithKind("ReplicaSet"):  &duckv1.WithPod{},
	appsv1.SchemeGroupVersion.WithKind("Deployment"):  &duckv1.WithPod{},
	appsv1.SchemeGroupVersion.WithKind("StatefulSet"): &duckv1.WithPod{},
	appsv1.SchemeGroupVersion.WithKind("DaemonSet"):   &duckv1.WithPod{},
	batchv1.SchemeGroupVersion.WithKind("Job"):        &duckv1.WithPod{},

	batchv1.SchemeGroupVersion.WithKind("CronJob"):      &duckv1.CronJob{},
	batchv1beta1.SchemeGroupVersion.WithKind("CronJob"): &duckv1.CronJob{},
}

func NewValidatingAdmissionController(ctx context.Context, cmw configmap.Watcher) *controller.Impl {
	// Decorate contexts with the current state of the config.
	store := config.NewStore(logging.FromContext(ctx).Named("config-store"))
	store.WatchConfigs(cmw)
	validator := review.NewValidator(ctx, secretName)

	return validation.NewAdmissionController(ctx,
		// Name of the resource webhook.
		webhookName,

		// The path on which to serve the webhook.
		"/validations",

		// The resources to validate.
		types,

		// A function that infuses the context passed to Validate/SetDefaults with custom metadata.
		func(ctx context.Context) context.Context {
			ctx = store.ToContext(ctx)
			ctx = duckv1.WithPodValidator(ctx, validator.ValidatePod)
			ctx = duckv1.WithPodSpecValidator(ctx, validator.ValidatePodSpecable)
			ctx = duckv1.WithCronJobValidator(ctx, validator.ValidateCronJob)
			return ctx
		},

		// Whether to disallow unknown fields.
		// We pass false because we're using partial schemas.
		false,

		// Extra validating callbacks to be applied to resources.
		nil,
	)
}
