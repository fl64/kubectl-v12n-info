package main

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

const (
	green   = "\033[32;1m"
	yellow  = "\033[33;1m"
	red     = "\033[31;1m"
	cyan    = "\033[36;1m"
	magenta = "\033[35;1m"
	blue    = "\033[34;1m"
	gray    = "\033[90;1m"
	reset   = "\033[0m"
)

var (
	systemResourceColor = yellow
	namespaceColor      = blue
	nodeColor           = magenta
	resourceColor       = cyan
)

type VM struct {
	Name            string
	Namespace       string
	NodeName        string
	IPAddress       string
	Phase           string
	BlockDeviceRefs []BlockDeviceRef
}

type BlockDeviceRef struct {
	Name string
	Kind string
}

type Pod struct {
	Name  string
	Phase string
}

type StorageResource struct {
	Name  string
	Phase string
}

type Clients struct {
	Kube    *kubernetes.Clientset
	Dynamic dynamic.Interface
}

func showPhase(phase string) string {
	switch phase {
	case "Bound", "Running", "Ready":
		return fmt.Sprintf("%s%s%s", green, phase, reset)
	case "Pending", "Starting":
		return fmt.Sprintf("%s%s%s", yellow, phase, reset)
	case "Succeeded", "Stopped":
		return fmt.Sprintf("%s%s%s", gray, phase, reset)
	default:
		return fmt.Sprintf("%s%s%s", red, phase, reset)
	}
}

var (
	configFlags         = genericclioptions.NewConfigFlags(true)
	allNamespaces       bool
	vmName              string
	showSystemResources bool
	rootCmd             = &cobra.Command{
		Use:   "v12n [vm-name] [flags]",
		Short: "Display information about VirtualMachines in Deckhouse Virtualization Platform",
		Long: `A kubectl plugin to show hierarchical information about VirtualMachines, Pods, BlockDevices, PVCs, and PVs in one or all namespaces.

Examples:
  # Show info for the current namespace (without system resources)
  kubectl v12n

  # Show info for the current namespace with pods, PVCs, and PVs
  kubectl v12n -S

  # Show info for a specific namespace
  kubectl v12n --namespace my-ns

  # Show info for a specific VM in the current namespace
  kubectl v12n my-vm

  # Show info for a specific VM with system resources
  kubectl v12n my-vm -S --namespace my-ns

  # Show info for all namespaces (without system resources)
  kubectl v12n --all-namespaces`,
		Args: cobra.MaximumNArgs(1),
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				vmName = args[0]
			}
			if allNamespaces && vmName != "" {
				return fmt.Errorf("cannot use --all-namespaces with a specific VM name")
			}
			return nil
		},
		RunE: runRoot,
	}
)

func init() {
	configFlags.AddFlags(rootCmd.PersistentFlags())
	rootCmd.Flags().BoolVarP(&allNamespaces, "all-namespaces", "A", allNamespaces, "If true, show information for all namespaces")
	rootCmd.Flags().StringVar(&vmName, "vm-name", "", "Name of a specific VirtualMachine to display")
	rootCmd.Flags().BoolVarP(&showSystemResources, "show-system-resources", "S", false, "If true, include system resources (pods, PVCs, PVs) in output")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func runRoot(cmd *cobra.Command, args []string) error {
	config, err := configFlags.ToRESTConfig()
	if err != nil {
		return fmt.Errorf("failed to create REST config: %w", err)
	}

	kubeClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("failed to create Kubernetes clientset: %w", err)
	}

	dynClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("failed to create dynamic client: %w", err)
	}

	clients := &Clients{
		Kube:    kubeClient,
		Dynamic: dynClient,
	}

	ctx := context.Background()

	if allNamespaces {
		nsList, err := clients.Kube.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
		if err != nil {
			return fmt.Errorf("failed to list namespaces: %w", err)
		}
		for _, ns := range nsList.Items {
			if err := displayNamespaceInfo(ctx, clients, ns.Name, vmName); err != nil {
				fmt.Fprintf(os.Stderr, "Error in namespace %s: %v\n", ns.Name, err)
			}
		}
	} else {
		namespace := ""
		if configFlags.Namespace != nil {
			namespace = *configFlags.Namespace
		}
		if namespace == "" {
			currentNs, _, err := configFlags.ToRawKubeConfigLoader().Namespace()
			if err != nil {
				return fmt.Errorf("failed to get current namespace: %w", err)
			}
			namespace = currentNs
		}
		if err := displayNamespaceInfo(ctx, clients, namespace, vmName); err != nil {
			return err
		}
	}
	return nil
}

func displayNamespaceInfo(ctx context.Context, clients *Clients, namespace, vmName string) error {
	fmt.Printf("◻ %s%s%s\n", namespaceColor, namespace, reset)

	vms, err := getVMs(ctx, clients.Dynamic, namespace)
	if err != nil {
		return fmt.Errorf("failed to get VMs in %s: %w", namespace, err)
	}
	if len(vms) == 0 {
		return nil
	}

	// Filter VMs if a specific VM name is provided
	if vmName != "" {
		vms = filterVMsByName(vms, vmName)
		if len(vms) == 0 {
			return fmt.Errorf("no VirtualMachine named %s found in namespace %s", vmName, namespace)
		}
	}

	nodes := make(map[string][]VM)
	for _, vm := range vms {
		nodes[vm.NodeName] = append(nodes[vm.NodeName], vm)
	}

	nodeNames := make([]string, 0, len(nodes))
	for nodeName := range nodes {
		nodeNames = append(nodeNames, nodeName)
	}
	sort.Strings(nodeNames)

	for _, nodeName := range nodeNames {
		fmt.Printf("  🖥 %s%s%s\n", nodeColor, nodeName, reset)
		for _, vm := range nodes[nodeName] {
			fmt.Printf("    ╰-🖳  %sVirtualMachine%s %s / %s : %s\n", resourceColor, reset, vm.Name, vm.IPAddress, showPhase(vm.Phase))

			if showSystemResources {
				pods, err := getPodForVM(ctx, clients.Kube, namespace, vm.Name)
				if err == nil {
					for _, pod := range pods {
						fmt.Printf("    ‧  ╰-⚙  %sPod%s %s : %s\n", systemResourceColor, reset, pod.Name, showPhase(pod.Phase))
					}
				}
			}

			for _, bd := range vm.BlockDeviceRefs {
				phase, err := getBlockDevicePhase(ctx, clients.Dynamic, namespace, bd.Name, bd.Kind)
				if err != nil {
					continue
				}
				fmt.Printf("    ‧  ╰-🖴  %s%s%s %s : %s\n", resourceColor, bd.Kind, reset, bd.Name, showPhase(phase))

				if showSystemResources && bd.Kind == "VirtualDisk" {
					pvc, pv, err := getPVCandPV(ctx, clients.Kube, clients.Dynamic, namespace, bd.Name)
					if err == nil {
						fmt.Printf("    ‧  ‧ ╰-⛃  %sPVC%s %s : %s\n", systemResourceColor, reset, pvc.Name, showPhase(pvc.Phase))
						fmt.Printf("    ‧  ‧   ╰-⛁  %sPV%s %s : %s\n", systemResourceColor, reset, pv.Name, showPhase(pv.Phase))
					}
				}
			}
		}
	}
	return nil
}

func filterVMsByName(vms []VM, vmName string) []VM {
	var filtered []VM
	for _, vm := range vms {
		if vm.Name == vmName {
			filtered = append(filtered, vm)
		}
	}
	return filtered
}

func getVMs(ctx context.Context, dynClient dynamic.Interface, namespace string) ([]VM, error) {
	gvr := schema.GroupVersionResource{Group: "virtualization.deckhouse.io", Version: "v1alpha2", Resource: "virtualmachines"}
	list, err := dynClient.Resource(gvr).Namespace(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	var vms []VM
	for _, item := range list.Items {
		vm := VM{
			Name:      item.GetName(),
			Namespace: item.GetNamespace(),
		}
		status, _, _ := unstructured.NestedMap(item.Object, "status")
		vm.NodeName = nestedString(status, "nodeName")
		vm.IPAddress = nestedString(status, "ipAddress")
		vm.Phase = nestedString(status, "phase")

		spec, _, _ := unstructured.NestedMap(item.Object, "spec")
		bdRefs, _, _ := unstructured.NestedSlice(spec, "blockDeviceRefs")
		for _, bd := range bdRefs {
			bdMap, ok := bd.(map[string]interface{})
			if ok {
				vm.BlockDeviceRefs = append(vm.BlockDeviceRefs, BlockDeviceRef{
					Name: nestedString(bdMap, "name"),
					Kind: nestedString(bdMap, "kind"),
				})
			}
		}
		vms = append(vms, vm)
	}
	return vms, nil
}

func getPodForVM(ctx context.Context, kubeClient *kubernetes.Clientset, namespace, vmName string) ([]Pod, error) {
	pods, err := kubeClient.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: fmt.Sprintf("vm.kubevirt.internal.virtualization.deckhouse.io/name=%s", vmName),
	})
	if err != nil || len(pods.Items) == 0 {
		return nil, err
	}
	var podList []Pod
	for _, pod := range pods.Items {
		podList = append(podList, Pod{
			Name:  pod.Name,
			Phase: string(pod.Status.Phase),
		})
	}
	return podList, nil
}

func getBlockDevicePhase(ctx context.Context, dynClient dynamic.Interface, namespace, name, kind string) (string, error) {
	var gvr schema.GroupVersionResource
	switch kind {
	case "VirtualDisk", "VirtualImage":
		gvr = schema.GroupVersionResource{Group: "virtualization.deckhouse.io", Version: "v1alpha2", Resource: strings.ToLower(kind) + "s"}
		res, err := dynClient.Resource(gvr).Namespace(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return "", err
		}
		return nestedString(res.Object, "status", "phase"), nil
	case "ClusterVirtualImage":
		gvr = schema.GroupVersionResource{Group: "virtualization.deckhouse.io", Version: "v1alpha2", Resource: "clustervirtualimages"}
		res, err := dynClient.Resource(gvr).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return "", err
		}
		return nestedString(res.Object, "status", "phase"), nil
	default:
		return "", fmt.Errorf("unsupported block device kind: %s", kind)
	}
}

func getPVCandPV(ctx context.Context, kubeClient *kubernetes.Clientset, dynClient dynamic.Interface, namespace, virtualDiskName string) (StorageResource, StorageResource, error) {
	gvr := schema.GroupVersionResource{Group: "virtualization.deckhouse.io", Version: "v1alpha2", Resource: "virtualdisks"}
	vd, err := dynClient.Resource(gvr).Namespace(namespace).Get(ctx, virtualDiskName, metav1.GetOptions{})
	if err != nil {
		return StorageResource{}, StorageResource{}, err
	}
	pvcName := nestedString(vd.Object, "status", "target", "persistentVolumeClaimName")
	if pvcName == "" {
		return StorageResource{}, StorageResource{}, fmt.Errorf("no PVC found for VirtualDisk %s", virtualDiskName)
	}

	pvc, err := kubeClient.CoreV1().PersistentVolumeClaims(namespace).Get(ctx, pvcName, metav1.GetOptions{})
	if err != nil {
		return StorageResource{}, StorageResource{}, err
	}

	pv, err := kubeClient.CoreV1().PersistentVolumes().Get(ctx, pvc.Spec.VolumeName, metav1.GetOptions{})
	if err != nil {
		return StorageResource{}, StorageResource{}, err
	}

	return StorageResource{Name: pvcName, Phase: string(pvc.Status.Phase)},
		StorageResource{Name: pvc.Spec.VolumeName, Phase: string(pv.Status.Phase)},
		nil
}

func nestedString(obj map[string]interface{}, keys ...string) string {
	val, found, _ := unstructured.NestedString(obj, keys...)
	if !found {
		return ""
	}
	return val
}
