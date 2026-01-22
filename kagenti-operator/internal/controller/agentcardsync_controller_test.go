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

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	agentv1alpha1 "github.com/kagenti/operator/api/v1alpha1"
)

var _ = Describe("AgentCardSync Controller", func() {
	Context("When reconciling an Agent with agent labels", func() {
		const (
			agentName     = "test-sync-agent"
			agentCardName = "test-sync-agent-card"
			namespace     = "default"
		)

		ctx := context.Background()

		agentNamespacedName := types.NamespacedName{
			Name:      agentName,
			Namespace: namespace,
		}

		BeforeEach(func() {
			By("creating an Agent with kagenti.io/type=agent label")
			agent := &agentv1alpha1.Agent{
				ObjectMeta: metav1.ObjectMeta{
					Name:      agentName,
					Namespace: namespace,
					Labels: map[string]string{
						"app.kubernetes.io/name": agentName,
						LabelAgentType:           LabelValueAgent,
						LabelAgentProtocol:       "a2a",
					},
				},
				Spec: agentv1alpha1.AgentSpec{
					PodTemplateSpec: &corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{
								{
									Name:  "agent",
									Image: "test-image:latest",
								},
							},
						},
					},
					Image: "test-image:latest",
				},
			}
			Expect(k8sClient.Create(ctx, agent)).To(Succeed())
		})

		AfterEach(func() {
			By("cleaning up the Agent resource")
			agent := &agentv1alpha1.Agent{}
			err := k8sClient.Get(ctx, agentNamespacedName, agent)
			if err == nil {
				Expect(k8sClient.Delete(ctx, agent)).To(Succeed())
			}

			By("cleaning up any created AgentCard resource")
			agentCard := &agentv1alpha1.AgentCard{}
			err = k8sClient.Get(ctx, types.NamespacedName{
				Name:      agentCardName,
				Namespace: namespace,
			}, agentCard)
			if err == nil {
				Expect(k8sClient.Delete(ctx, agentCard)).To(Succeed())
			}
		})

		It("should automatically create an AgentCard", func() {
			By("reconciling the Agent")
			reconciler := &AgentCardSyncReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: agentNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			By("checking that an AgentCard was created")
			agentCard := &agentv1alpha1.AgentCard{}
			Eventually(func() bool {
				err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      agentCardName,
					Namespace: namespace,
				}, agentCard)
				return err == nil
			}).Should(BeTrue())

			By("verifying the AgentCard has correct selector")
			Expect(agentCard.Spec.Selector.MatchLabels).To(HaveKeyWithValue("app.kubernetes.io/name", agentName))
			Expect(agentCard.Spec.Selector.MatchLabels).To(HaveKeyWithValue(LabelAgentType, LabelValueAgent))

			By("verifying the AgentCard has owner reference")
			Expect(agentCard.OwnerReferences).NotTo(BeEmpty())
			Expect(agentCard.OwnerReferences[0].Kind).To(Equal("Agent"))
			Expect(agentCard.OwnerReferences[0].Name).To(Equal(agentName))
		})

		It("should not create AgentCard for agents without protocol label", func() {
			const agentNoProtocol = "test-no-protocol-agent"

			By("creating an Agent without protocol label")
			agent := &agentv1alpha1.Agent{
				ObjectMeta: metav1.ObjectMeta{
					Name:      agentNoProtocol,
					Namespace: namespace,
					Labels: map[string]string{
						LabelAgentType: LabelValueAgent,
						// No protocol label
					},
				},
				Spec: agentv1alpha1.AgentSpec{
					PodTemplateSpec: &corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{
								{
									Name:  "agent",
									Image: "test-image:latest",
								},
							},
						},
					},
					Image: "test-image:latest",
				},
			}
			Expect(k8sClient.Create(ctx, agent)).To(Succeed())

			By("reconciling the Agent")
			reconciler := &AgentCardSyncReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      agentNoProtocol,
					Namespace: namespace,
				},
			})
			Expect(err).NotTo(HaveOccurred())

			By("verifying no AgentCard was created")
			agentCard := &agentv1alpha1.AgentCard{}
			err = k8sClient.Get(ctx, types.NamespacedName{
				Name:      agentNoProtocol + "-card",
				Namespace: namespace,
			}, agentCard)
			Expect(errors.IsNotFound(err)).To(BeTrue())

			By("cleaning up the test Agent")
			Expect(k8sClient.Delete(ctx, agent)).To(Succeed())
		})
	})
})
