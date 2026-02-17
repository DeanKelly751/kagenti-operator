/*
Copyright 2025.

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

package controller

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	agentv1alpha1 "github.com/kagenti/operator/api/v1alpha1"
	"github.com/kagenti/operator/internal/signature"
)

var _ = Describe("Identity Binding", func() {
	const (
		timeout  = time.Second * 10
		interval = time.Millisecond * 250
	)

	Context("AgentCard Binding Evaluation - Matching", func() {
		const (
			deploymentName = "bind-eval-match-deploy"
			agentCardName  = "bind-eval-match-card"
			secretName     = "bind-eval-match-keys"
			namespace      = "default"
			trustDomain    = "test.local"
		)

		ctx := context.Background()

		AfterEach(func() {
			By("cleaning up test resources")
			cleanupResource(ctx, &agentv1alpha1.AgentCard{}, agentCardName, namespace)
			cleanupResource(ctx, &appsv1.Deployment{}, deploymentName, namespace)
			cleanupResource(ctx, &corev1.Service{}, deploymentName, namespace)
			cleanupResource(ctx, &corev1.Secret{}, secretName, namespace)
		})

		It("should evaluate binding as Bound when SPIFFE ID matches allowlist", func() {
			By("generating an RSA key pair")
			privKey, err := rsa.GenerateKey(rand.Reader, 2048)
			Expect(err).NotTo(HaveOccurred())
			pubDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
			Expect(err).NotTo(HaveOccurred())
			pubKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

			By("creating the public key Secret")
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: secretName, Namespace: namespace},
				Data:       map[string][]byte{"signing-key": pubKeyPEM},
			}
			Expect(k8sClient.Create(ctx, secret)).To(Succeed())

			By("creating a Deployment with agent labels")
			labels := map[string]string{
				"app.kubernetes.io/name": deploymentName,
				LabelAgentType:           LabelValueAgent,
				LabelKagentiProtocol:     "a2a",
			}
			deployment := &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Name:      deploymentName,
					Namespace: namespace,
					Labels:    labels,
				},
				Spec: appsv1.DeploymentSpec{
					Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": deploymentName}},
					Template: corev1.PodTemplateSpec{
						ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": deploymentName}},
						Spec: corev1.PodSpec{
							ServiceAccountName: "test-sa",
							Containers: []corev1.Container{
								{Name: "agent", Image: "test-image:latest"},
							},
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, deployment)).To(Succeed())

			By("setting Deployment status to Available")
			Eventually(func() error {
				if err := k8sClient.Get(ctx, types.NamespacedName{Name: deploymentName, Namespace: namespace}, deployment); err != nil {
					return err
				}
				deployment.Status.Conditions = []appsv1.DeploymentCondition{
					{Type: appsv1.DeploymentAvailable, Status: corev1.ConditionTrue},
				}
				return k8sClient.Status().Update(ctx, deployment)
			}).Should(Succeed())

			By("creating a Service for the Deployment")
			service := &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      deploymentName,
					Namespace: namespace,
				},
				Spec: corev1.ServiceSpec{
					Ports: []corev1.ServicePort{
						{Name: "http", Port: 8000, Protocol: corev1.ProtocolTCP},
					},
					Selector: map[string]string{"app": deploymentName},
				},
			}
			Expect(k8sClient.Create(ctx, service)).To(Succeed())

			By("creating signed card data with SPIFFE ID in JWS protected header")
			expectedSpiffeID := "spiffe://" + trustDomain + "/ns/" + namespace + "/sa/test-sa"
			cardData := &agentv1alpha1.AgentCardData{
				Name:    "Test Agent",
				Version: "1.0.0",
				URL:     "http://localhost:8000",
			}
			jwsSig := buildTestJWS(cardData, privKey, "key-1", expectedSpiffeID)
			cardData.Signatures = []agentv1alpha1.AgentCardSignature{jwsSig}

			By("creating an AgentCard with identity binding")
			agentCard := &agentv1alpha1.AgentCard{
				ObjectMeta: metav1.ObjectMeta{
					Name:      agentCardName,
					Namespace: namespace,
				},
				Spec: agentv1alpha1.AgentCardSpec{
					SyncPeriod: "30s",
					TargetRef: &agentv1alpha1.TargetRef{
						APIVersion: "apps/v1",
						Kind:       "Deployment",
						Name:       deploymentName,
					},
					IdentityBinding: &agentv1alpha1.IdentityBinding{
						AllowedSpiffeIDs: []agentv1alpha1.SpiffeID{agentv1alpha1.SpiffeID(expectedSpiffeID)},
						Strict:           false,
					},
				},
			}
			Expect(k8sClient.Create(ctx, agentCard)).To(Succeed())

			By("setting up reconciler with signature verification")
			provider, err := signature.NewSecretProvider(&signature.Config{
				Type:            signature.ProviderTypeSecret,
				SecretName:      secretName,
				SecretNamespace: namespace,
			})
			Expect(err).NotTo(HaveOccurred())
			provider.(*signature.SecretProvider).SetClient(k8sClient)

			reconciler := &AgentCardReconciler{
				Client:            k8sClient,
				Scheme:            k8sClient.Scheme(),
				AgentFetcher:      &mockFetcher{cardData: cardData},
				RequireSignature:  true,
				SignatureProvider: provider,
			}

			By("reconciling the AgentCard (first reconcile adds finalizer)")
			_, err = reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: agentCardName, Namespace: namespace},
			})
			Expect(err).NotTo(HaveOccurred())

			By("reconciling again (verifies signature and evaluates binding in one pass)")
			_, err = reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: agentCardName, Namespace: namespace},
			})
			Expect(err).NotTo(HaveOccurred())

			By("verifying binding status is Bound")
			Eventually(func() bool {
				card := &agentv1alpha1.AgentCard{}
				if err := k8sClient.Get(ctx, types.NamespacedName{Name: agentCardName, Namespace: namespace}, card); err != nil {
					return false
				}
				return card.Status.BindingStatus != nil && card.Status.BindingStatus.Bound
			}, timeout, interval).Should(BeTrue())

			By("verifying expected SPIFFE ID is set")
			card := &agentv1alpha1.AgentCard{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: agentCardName, Namespace: namespace}, card)).To(Succeed())
			Expect(card.Status.ExpectedSpiffeID).To(Equal(expectedSpiffeID))
			Expect(card.Status.BindingStatus.Reason).To(Equal(ReasonBound))
		})

	})

	Context("AgentCard Binding Evaluation - NonMatching", func() {
		const (
			deploymentName = "bind-eval-nomatch-deploy"
			agentCardName  = "bind-eval-nomatch-card"
			secretName     = "bind-eval-nomatch-keys"
			namespace      = "default"
			trustDomain    = "test.local"
		)

		ctx := context.Background()

		AfterEach(func() {
			By("cleaning up test resources")
			cleanupResource(ctx, &agentv1alpha1.AgentCard{}, agentCardName, namespace)
			cleanupResource(ctx, &appsv1.Deployment{}, deploymentName, namespace)
			cleanupResource(ctx, &corev1.Service{}, deploymentName, namespace)
			cleanupResource(ctx, &corev1.Secret{}, secretName, namespace)
		})

		It("should evaluate binding as NotBound when SPIFFE ID is not in allowlist", func() {
			By("generating an RSA key pair")
			privKey, err := rsa.GenerateKey(rand.Reader, 2048)
			Expect(err).NotTo(HaveOccurred())
			pubDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
			Expect(err).NotTo(HaveOccurred())
			pubKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

			By("creating the public key Secret")
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: secretName, Namespace: namespace},
				Data:       map[string][]byte{"signing-key": pubKeyPEM},
			}
			Expect(k8sClient.Create(ctx, secret)).To(Succeed())

			By("creating a Deployment with agent labels")
			labels := map[string]string{
				"app.kubernetes.io/name": deploymentName,
				LabelAgentType:           LabelValueAgent,
				LabelKagentiProtocol:     "a2a",
			}
			deployment := &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Name:      deploymentName,
					Namespace: namespace,
					Labels:    labels,
				},
				Spec: appsv1.DeploymentSpec{
					Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": deploymentName}},
					Template: corev1.PodTemplateSpec{
						ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": deploymentName}},
						Spec: corev1.PodSpec{
							ServiceAccountName: "test-sa",
							Containers: []corev1.Container{
								{Name: "agent", Image: "test-image:latest"},
							},
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, deployment)).To(Succeed())

			By("setting Deployment status to Available")
			Eventually(func() error {
				if err := k8sClient.Get(ctx, types.NamespacedName{Name: deploymentName, Namespace: namespace}, deployment); err != nil {
					return err
				}
				deployment.Status.Conditions = []appsv1.DeploymentCondition{
					{Type: appsv1.DeploymentAvailable, Status: corev1.ConditionTrue},
				}
				return k8sClient.Status().Update(ctx, deployment)
			}).Should(Succeed())

			By("creating a Service for the Deployment")
			service := &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      deploymentName,
					Namespace: namespace,
				},
				Spec: corev1.ServiceSpec{
					Ports: []corev1.ServicePort{
						{Name: "http", Port: 8000, Protocol: corev1.ProtocolTCP},
					},
					Selector: map[string]string{"app": deploymentName},
				},
			}
			Expect(k8sClient.Create(ctx, service)).To(Succeed())

			By("creating signed card data with SPIFFE ID that doesn't match allowlist")
			// JWS SPIFFE ID will NOT match the allowlist → binding should fail
			jwsSpiffeID := "spiffe://" + trustDomain + "/ns/" + namespace + "/sa/test-sa"
			cardData := &agentv1alpha1.AgentCardData{
				Name:    "Test Agent",
				Version: "1.0.0",
				URL:     "http://localhost:8000",
			}
			jwsSig := buildTestJWS(cardData, privKey, "key-1", jwsSpiffeID)
			cardData.Signatures = []agentv1alpha1.AgentCardSignature{jwsSig}

			By("creating an AgentCard with identity binding (allowlist does NOT include the JWS SPIFFE ID)")
			agentCard := &agentv1alpha1.AgentCard{
				ObjectMeta: metav1.ObjectMeta{
					Name:      agentCardName,
					Namespace: namespace,
				},
				Spec: agentv1alpha1.AgentCardSpec{
					SyncPeriod: "30s",
					TargetRef: &agentv1alpha1.TargetRef{
						APIVersion: "apps/v1",
						Kind:       "Deployment",
						Name:       deploymentName,
					},
					IdentityBinding: &agentv1alpha1.IdentityBinding{
						AllowedSpiffeIDs: []agentv1alpha1.SpiffeID{"spiffe://" + trustDomain + "/ns/other/sa/other-sa"},
						Strict:           false,
					},
				},
			}
			Expect(k8sClient.Create(ctx, agentCard)).To(Succeed())

			By("setting up reconciler with signature verification")
			provider, err := signature.NewSecretProvider(&signature.Config{
				Type:            signature.ProviderTypeSecret,
				SecretName:      secretName,
				SecretNamespace: namespace,
			})
			Expect(err).NotTo(HaveOccurred())
			provider.(*signature.SecretProvider).SetClient(k8sClient)

			reconciler := &AgentCardReconciler{
				Client:            k8sClient,
				Scheme:            k8sClient.Scheme(),
				AgentFetcher:      &mockFetcher{cardData: cardData},
				RequireSignature:  true,
				SignatureProvider: provider,
			}

			By("reconciling the AgentCard (first reconcile adds finalizer)")
			_, err = reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: agentCardName, Namespace: namespace},
			})
			Expect(err).NotTo(HaveOccurred())

			By("reconciling again (verifies signature and evaluates binding — SPIFFE ID not in allowlist)")
			_, err = reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: agentCardName, Namespace: namespace},
			})
			Expect(err).NotTo(HaveOccurred())

			By("verifying binding status is NotBound")
			Eventually(func() bool {
				card := &agentv1alpha1.AgentCard{}
				if err := k8sClient.Get(ctx, types.NamespacedName{Name: agentCardName, Namespace: namespace}, card); err != nil {
					return false
				}
				return card.Status.BindingStatus != nil && !card.Status.BindingStatus.Bound
			}, timeout, interval).Should(BeTrue())

			By("verifying reason is NotBound")
			card := &agentv1alpha1.AgentCard{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: agentCardName, Namespace: namespace}, card)).To(Succeed())
			Expect(card.Status.BindingStatus.Reason).To(Equal(ReasonNotBound))
		})
	})

	Context("Card ID Drift Detection", func() {
		It("should compute consistent card ID for same card data", func() {
			reconciler := &AgentCardReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			cardData := &agentv1alpha1.AgentCardData{
				Name:        "Test Agent",
				Description: "A test agent",
				Version:     "1.0.0",
				URL:         "http://localhost:8000",
			}

			cardId1 := reconciler.computeCardId(cardData)
			cardId2 := reconciler.computeCardId(cardData)

			Expect(cardId1).NotTo(BeEmpty())
			Expect(cardId1).To(Equal(cardId2))
		})

		It("should compute different card ID for different card data", func() {
			reconciler := &AgentCardReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			cardData1 := &agentv1alpha1.AgentCardData{
				Name:    "Test Agent",
				Version: "1.0.0",
			}

			cardData2 := &agentv1alpha1.AgentCardData{
				Name:    "Test Agent",
				Version: "2.0.0",
			}

			cardId1 := reconciler.computeCardId(cardData1)
			cardId2 := reconciler.computeCardId(cardData2)

			Expect(cardId1).NotTo(BeEmpty())
			Expect(cardId2).NotTo(BeEmpty())
			Expect(cardId1).NotTo(Equal(cardId2))
		})
	})

	Context("SPIFFE ID Source — JWS Protected Header Only", func() {
		It("should fail binding when no SPIFFE ID is in the JWS protected header", func() {
			reconciler := &AgentCardReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			agentCard := &agentv1alpha1.AgentCard{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "no-spiffe-card",
					Namespace: "default",
				},
				Spec: agentv1alpha1.AgentCardSpec{
					IdentityBinding: &agentv1alpha1.IdentityBinding{
						AllowedSpiffeIDs: []agentv1alpha1.SpiffeID{"spiffe://example.com/ns/default/sa/test"},
					},
				},
			}
			Expect(k8sClient.Create(ctx, agentCard)).To(Succeed())
			defer func() {
				cleanupResource(ctx, &agentv1alpha1.AgentCard{}, "no-spiffe-card", "default")
			}()

			// No verified SPIFFE ID → binding fails
			result := reconciler.computeBinding(agentCard, "")
			Expect(result).NotTo(BeNil())
			Expect(result.Bound).To(BeFalse())
		})

		It("should bind when JWS SPIFFE ID matches the allowlist", func() {
			reconciler := &AgentCardReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			jwsSpiffeID := "spiffe://example.com/ns/default/sa/from-jws"

			agentCard := &agentv1alpha1.AgentCard{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "jws-spiffe-card",
					Namespace: "default",
				},
				Spec: agentv1alpha1.AgentCardSpec{
					IdentityBinding: &agentv1alpha1.IdentityBinding{
						AllowedSpiffeIDs: []agentv1alpha1.SpiffeID{agentv1alpha1.SpiffeID(jwsSpiffeID)},
					},
				},
			}
			Expect(k8sClient.Create(ctx, agentCard)).To(Succeed())
			defer func() {
				cleanupResource(ctx, &agentv1alpha1.AgentCard{}, "jws-spiffe-card", "default")
			}()

			// Verified SPIFFE ID matches allowlist → binding passes
			result := reconciler.computeBinding(agentCard, jwsSpiffeID)
			Expect(result).NotTo(BeNil())
			Expect(result.Bound).To(BeTrue())
		})

		It("should bind when verified SPIFFE ID matches 2nd entry in allowlist", func() {
			reconciler := &AgentCardReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			verifiedSpiffeID := "spiffe://example.com/ns/default/sa/second-match"

			agentCard := &agentv1alpha1.AgentCard{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "multi-allowlist-card",
					Namespace: "default",
				},
				Spec: agentv1alpha1.AgentCardSpec{
					IdentityBinding: &agentv1alpha1.IdentityBinding{
						AllowedSpiffeIDs: []agentv1alpha1.SpiffeID{
							"spiffe://example.com/ns/default/sa/first",
							agentv1alpha1.SpiffeID(verifiedSpiffeID),
							"spiffe://example.com/ns/default/sa/third",
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, agentCard)).To(Succeed())
			defer func() {
				cleanupResource(ctx, &agentv1alpha1.AgentCard{}, "multi-allowlist-card", "default")
			}()

			// Verified SPIFFE ID matches 2nd entry → binding passes
			result := reconciler.computeBinding(agentCard, verifiedSpiffeID)
			Expect(result).NotTo(BeNil())
			Expect(result.Bound).To(BeTrue())
		})

		It("should not bind when allowedSpiffeIDs is empty (bypassed validation)", func() {
			reconciler := &AgentCardReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			// Craft an in-memory AgentCard with empty allowedSpiffeIDs — bypassing CRD validation
			// to simulate a scenario where validation was somehow bypassed.
			agentCard := &agentv1alpha1.AgentCard{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "empty-allowlist-card",
					Namespace: "default",
				},
				Spec: agentv1alpha1.AgentCardSpec{
					IdentityBinding: &agentv1alpha1.IdentityBinding{
						AllowedSpiffeIDs: []agentv1alpha1.SpiffeID{},
					},
				},
			}
			// Do NOT create via API — CRD enforces minItems=1. Test computeBinding directly.

			// Empty allowlist should always fail binding with BUG log
			result := reconciler.computeBinding(agentCard, "spiffe://example.com/ns/default/sa/test")
			Expect(result).NotTo(BeNil())
			Expect(result.Bound).To(BeFalse())
			Expect(result.Message).To(ContainSubstring("allowedSpiffeIDs is empty"))
		})

		It("should not trust JWS SPIFFE ID when signature is invalid", func() {
			reconciler := &AgentCardReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			jwsSpiffeID := "spiffe://example.com/ns/default/sa/from-jws"

			agentCard := &agentv1alpha1.AgentCard{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "invalid-sig-spiffe-card",
					Namespace: "default",
				},
				Spec: agentv1alpha1.AgentCardSpec{
					IdentityBinding: &agentv1alpha1.IdentityBinding{
						AllowedSpiffeIDs: []agentv1alpha1.SpiffeID{agentv1alpha1.SpiffeID(jwsSpiffeID)},
					},
				},
			}
			Expect(k8sClient.Create(ctx, agentCard)).To(Succeed())
			defer func() {
				cleanupResource(ctx, &agentv1alpha1.AgentCard{}, "invalid-sig-spiffe-card", "default")
			}()

			// Invalid signature → caller passes empty string (never trusts unverified SPIFFE ID) → fails
			result := reconciler.computeBinding(agentCard, "")
			Expect(result).NotTo(BeNil())
			Expect(result.Bound).To(BeFalse())
		})
	})

})

// cleanupResource removes a resource and waits for it to be fully deleted
func cleanupResource(ctx context.Context, obj client.Object, name, namespace string) {
	key := types.NamespacedName{Name: name, Namespace: namespace}

	// Try to get the object
	if err := k8sClient.Get(ctx, key, obj); err != nil {
		return // Object doesn't exist, nothing to clean up
	}

	// Remove finalizers to allow deletion
	obj.SetFinalizers(nil)
	_ = k8sClient.Update(ctx, obj)

	// Delete the object
	_ = k8sClient.Delete(ctx, obj)

	// Wait for deletion to complete
	Eventually(func() bool {
		err := k8sClient.Get(ctx, key, obj)
		return err != nil // Returns true when object is gone
	}, time.Second*5, time.Millisecond*100).Should(BeTrue())
}
