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
	_ "k8s.io/client-go/plugin/pkg/client/auth/oidc"
)

// Constants for colors
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

// Color scheme
var (
	systemResourceColor = yellow
	namespaceColor      = blue
	nodeColor           = magenta
	resourceColor       = cyan
)

// Resource interfaces for better abstraction
type Resource interface {
	GetName() string
	GetNamespace() string
	GetPhase() string
	GetDisplayInfo() string
}

type SystemResource interface {
	GetName() string
	GetPhase() string
	GetDisplayInfo() string
}

// Concrete resource types
type VM struct {
	Name            string
	Namespace       string
	NodeName        string
	IPAddress       string
	Phase           string
	BlockDeviceRefs []BlockDeviceRef
}

func (v VM) GetName() string        { return v.Name }
func (v VM) GetNamespace() string   { return v.Namespace }
func (v VM) GetPhase() string       { return v.Phase }
func (v VM) GetDisplayInfo() string { return fmt.Sprintf("%s / %s", v.Name, v.IPAddress) }

type BlockDeviceRef struct {
	Name string
	Kind string
}

type Pod struct {
	Name  string
	Phase string
}

func (p Pod) GetName() string        { return p.Name }
func (p Pod) GetNamespace() string   { return "" }
func (p Pod) GetPhase() string       { return p.Phase }
func (p Pod) GetDisplayInfo() string { return p.Name }

type StorageResource struct {
	Name  string
	Phase string
}

func (s StorageResource) GetName() string        { return s.Name }
func (s StorageResource) GetNamespace() string   { return "" }
func (s StorageResource) GetPhase() string       { return s.Phase }
func (s StorageResource) GetDisplayInfo() string { return s.Name }

type VirtualDisk struct {
	Name      string
	Namespace string
	Phase     string
	Size      string
}

func (vd VirtualDisk) GetName() string      { return vd.Name }
func (vd VirtualDisk) GetNamespace() string { return vd.Namespace }
func (vd VirtualDisk) GetPhase() string     { return vd.Phase }
func (vd VirtualDisk) GetDisplayInfo() string {
	if vd.Size != "" {
		return fmt.Sprintf("%s (%s)", vd.Name, vd.Size)
	}
	return vd.Name
}

// Clients interface for better testability
type Clients interface {
	GetKubeClient() *kubernetes.Clientset
	GetDynamicClient() dynamic.Interface
}

type KubernetesClients struct {
	Kube    *kubernetes.Clientset
	Dynamic dynamic.Interface
}

func (k *KubernetesClients) GetKubeClient() *kubernetes.Clientset { return k.Kube }
func (k *KubernetesClients) GetDynamicClient() dynamic.Interface  { return k.Dynamic }

// Resource provider interface
type ResourceProvider interface {
	GetResources(ctx context.Context, clients Clients, namespace string) ([]Resource, error)
	GetResourceType() string
	GetDisplayIcon() string
}

// VM resource provider
type VMProvider struct{}

func (p *VMProvider) GetResourceType() string { return "VirtualMachine" }
func (p *VMProvider) GetDisplayIcon() string  { return "🖳" }

func (p *VMProvider) GetResources(ctx context.Context, clients Clients, namespace string) ([]Resource, error) {
	gvr := schema.GroupVersionResource{Group: "virtualization.deckhouse.io", Version: "v1alpha2", Resource: "virtualmachines"}
	list, err := clients.GetDynamicClient().Resource(gvr).Namespace(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	var resources []Resource
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
		resources = append(resources, vm)
	}
	return resources, nil
}

// VirtualDisk resource provider
type VDProvider struct{}

func (p *VDProvider) GetResourceType() string { return "VirtualDisk" }
func (p *VDProvider) GetDisplayIcon() string  { return "🖴" }

func (p *VDProvider) GetResources(ctx context.Context, clients Clients, namespace string) ([]Resource, error) {
	gvr := schema.GroupVersionResource{Group: "virtualization.deckhouse.io", Version: "v1alpha2", Resource: "virtualdisks"}
	list, err := clients.GetDynamicClient().Resource(gvr).Namespace(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	var resources []Resource
	for _, item := range list.Items {
		disk := VirtualDisk{
			Name:      item.GetName(),
			Namespace: item.GetNamespace(),
		}
		status, _, _ := unstructured.NestedMap(item.Object, "status")
		disk.Phase = nestedString(status, "phase")
		disk.Size = nestedString(status, "size")
		resources = append(resources, disk)
	}
	return resources, nil
}

// System resource providers
type SystemResourceProvider interface {
	GetSystemResources(ctx context.Context, clients Clients, namespace string, resourceName string) ([]SystemResource, error)
	GetDisplayIcon() string
}

type PodProvider struct{}

func (p *PodProvider) GetDisplayIcon() string { return "⚙" }

func (p *PodProvider) GetSystemResources(ctx context.Context, clients Clients, namespace string, vmName string) ([]SystemResource, error) {
	pods, err := clients.GetKubeClient().CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: fmt.Sprintf("vm.kubevirt.internal.virtualization.deckhouse.io/name=%s", vmName),
	})
	if err != nil || len(pods.Items) == 0 {
		return nil, err
	}

	var resources []SystemResource
	for _, pod := range pods.Items {
		resources = append(resources, Pod{
			Name:  pod.Name,
			Phase: string(pod.Status.Phase),
		})
	}
	return resources, nil
}

type PVCProvider struct{}

func (p *PVCProvider) GetDisplayIcon() string { return "⛃" }

func (p *PVCProvider) GetSystemResources(ctx context.Context, clients Clients, namespace string, virtualDiskName string) ([]SystemResource, error) {
	gvr := schema.GroupVersionResource{Group: "virtualization.deckhouse.io", Version: "v1alpha2", Resource: "virtualdisks"}
	vd, err := clients.GetDynamicClient().Resource(gvr).Namespace(namespace).Get(ctx, virtualDiskName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	pvcName := nestedString(vd.Object, "status", "target", "persistentVolumeClaimName")
	if pvcName == "" {
		return nil, fmt.Errorf("no PVC found for VirtualDisk %s", virtualDiskName)
	}

	pvc, err := clients.GetKubeClient().CoreV1().PersistentVolumeClaims(namespace).Get(ctx, pvcName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	return []SystemResource{StorageResource{Name: pvcName, Phase: string(pvc.Status.Phase)}}, nil
}

type PVProvider struct{}

func (p *PVProvider) GetDisplayIcon() string { return "⛁" }

func (p *PVProvider) GetSystemResources(ctx context.Context, clients Clients, namespace string, virtualDiskName string) ([]SystemResource, error) {
	gvr := schema.GroupVersionResource{Group: "virtualization.deckhouse.io", Version: "v1alpha2", Resource: "virtualdisks"}
	vd, err := clients.GetDynamicClient().Resource(gvr).Namespace(namespace).Get(ctx, virtualDiskName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	pvcName := nestedString(vd.Object, "status", "target", "persistentVolumeClaimName")
	if pvcName == "" {
		return nil, fmt.Errorf("no PVC found for VirtualDisk %s", virtualDiskName)
	}

	pvc, err := clients.GetKubeClient().CoreV1().PersistentVolumeClaims(namespace).Get(ctx, pvcName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	pv, err := clients.GetKubeClient().CoreV1().PersistentVolumes().Get(ctx, pvc.Spec.VolumeName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	return []SystemResource{StorageResource{Name: pvc.Spec.VolumeName, Phase: string(pv.Status.Phase)}}, nil
}

// Display service for rendering output
type DisplayService struct{}

func (d *DisplayService) ShowPhase(phase string) string {
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

func (d *DisplayService) ShowNamespace(namespace string) {
	fmt.Printf("◻ %s%s%s\n", namespaceColor, namespace, reset)
}

func (d *DisplayService) ShowResource(icon, resourceType, name, info string, phase string) {
	fmt.Printf("  └─ %s  %s%s%s %s : %s\n", icon, resourceColor, resourceType, reset, info, d.ShowPhase(phase))
}

func (d *DisplayService) ShowSystemResource(icon, resourceType, name, phase string) {
	fmt.Printf("    │  └─ %s  %s%s%s %s : %s\n", icon, systemResourceColor, resourceType, reset, name, d.ShowPhase(phase))
}

func (d *DisplayService) ShowNestedSystemResource(icon, resourceType, name, phase string, isLast bool) {
	var prefix string
	if isLast {
		prefix = "    │  └─"
	} else {
		prefix = "    │  ├─"
	}
	fmt.Printf("%s %s  %s%s%s %s : %s\n", prefix, icon, systemResourceColor, resourceType, reset, name, d.ShowPhase(phase))
}

func (d *DisplayService) ShowDeepNestedSystemResource(icon, resourceType, name, phase string, isLast bool) {
	var prefix string
	if isLast {
		prefix = "    │     └─"
	} else {
		prefix = "    │     ├─"
	}
	fmt.Printf("%s %s  %s%s%s %s : %s\n", prefix, icon, systemResourceColor, resourceType, reset, name, d.ShowPhase(phase))
}

func (d *DisplayService) ShowNode(nodeName string) {
	fmt.Printf("  🖥 %s%s%s\n", nodeColor, nodeName, reset)
}

func (d *DisplayService) ShowResourceGroup(icon, resourceType string) {
	fmt.Printf("  %s %s%s%s\n", icon, resourceColor, resourceType, reset)
}

// Command runner interface
type CommandRunner interface {
	Run(ctx context.Context, clients Clients, namespace string, resourceName string) error
}

// Base command runner
type BaseCommandRunner struct {
	provider ResourceProvider
	display  *DisplayService
}

func (r *BaseCommandRunner) Run(ctx context.Context, clients Clients, namespace string, resourceName string) error {
	resources, err := r.provider.GetResources(ctx, clients, namespace)
	if err != nil {
		return fmt.Errorf("failed to get %s in %s: %w", r.provider.GetResourceType(), namespace, err)
	}

	if len(resources) == 0 {
		return nil
	}

	// Filter resources if a specific name is provided
	if resourceName != "" {
		resources = r.filterResourcesByName(resources, resourceName)
		if len(resources) == 0 {
			return fmt.Errorf("no %s named %s found in namespace %s", r.provider.GetResourceType(), resourceName, namespace)
		}
	}

	r.display.ShowNamespace(namespace)
	r.display.ShowResourceGroup(r.provider.GetDisplayIcon(), r.provider.GetResourceType()+"s")

	for _, resource := range resources {
		fmt.Printf("  └─ %s : %s\n", resource.GetDisplayInfo(), r.display.ShowPhase(resource.GetPhase()))
	}

	return nil
}

func (r *BaseCommandRunner) filterResourcesByName(resources []Resource, name string) []Resource {
	var filtered []Resource
	for _, resource := range resources {
		if resource.GetName() == name {
			filtered = append(filtered, resource)
		}
	}
	return filtered
}

// VM command runner with special logic for nodes and system resources
type VMCommandRunner struct {
	BaseCommandRunner
	showSystemResources bool
}

func (r *VMCommandRunner) Run(ctx context.Context, clients Clients, namespace string, resourceName string) error {
	resources, err := r.provider.GetResources(ctx, clients, namespace)
	if err != nil {
		return fmt.Errorf("failed to get %s in %s: %w", r.provider.GetResourceType(), namespace, err)
	}

	if len(resources) == 0 {
		return nil
	}

	// Filter VMs if a specific VM name is provided
	if resourceName != "" {
		resources = r.filterResourcesByName(resources, resourceName)
		if len(resources) == 0 {
			return fmt.Errorf("no %s named %s found in namespace %s", r.provider.GetResourceType(), resourceName, namespace)
		}
	}

	// Group VMs by node
	nodes := make(map[string][]VM)
	for _, resource := range resources {
		if vm, ok := resource.(VM); ok {
			nodeKey := vm.NodeName
			if nodeKey == "" {
				nodeKey = "<not scheduled>"
			}
			nodes[nodeKey] = append(nodes[nodeKey], vm)
		}
	}

	nodeNames := make([]string, 0, len(nodes))
	for nodeName := range nodes {
		nodeNames = append(nodeNames, nodeName)
	}
	sort.Strings(nodeNames)

	r.display.ShowNamespace(namespace)
	for _, nodeName := range nodeNames {
		r.display.ShowNode(nodeName)
		for _, vm := range nodes[nodeName] {
			r.display.ShowResource(r.provider.GetDisplayIcon(), r.provider.GetResourceType(), vm.Name, vm.GetDisplayInfo(), vm.GetPhase())

			if r.showSystemResources {
				r.showSystemResourcesForVM(ctx, clients, namespace, vm)
			}

			r.showBlockDevicesForVM(ctx, clients, namespace, vm)
		}
	}

	return nil
}

func (r *VMCommandRunner) showSystemResourcesForVM(ctx context.Context, clients Clients, namespace string, vm VM) {
	podProvider := &PodProvider{}
	pods, err := podProvider.GetSystemResources(ctx, clients, namespace, vm.Name)
	if err == nil {
		for _, pod := range pods {
			r.display.ShowSystemResource(podProvider.GetDisplayIcon(), "Pod", pod.GetDisplayInfo(), pod.GetPhase())
		}
	}
}

func (r *VMCommandRunner) showBlockDevicesForVM(ctx context.Context, clients Clients, namespace string, vm VM) {
	for i, bd := range vm.BlockDeviceRefs {
		phase, err := r.getBlockDevicePhase(ctx, clients, namespace, bd.Name, bd.Kind)
		if err != nil {
			continue
		}

		hasSystemResources := r.showSystemResources && bd.Kind == "VirtualDisk"
		isLast := i == len(vm.BlockDeviceRefs)-1 && !hasSystemResources

		var prefix string
		if isLast {
			prefix = "    └─"
		} else {
			prefix = "    ├─"
		}

		fmt.Printf("%s 🖴  %s%s%s %s : %s\n", prefix, resourceColor, bd.Kind, reset, bd.Name, r.display.ShowPhase(phase))

		if hasSystemResources {
			r.showStorageResourcesForDisk(ctx, clients, namespace, bd.Name, i == len(vm.BlockDeviceRefs)-1)
		}
	}
}

func (r *VMCommandRunner) showStorageResourcesForDisk(ctx context.Context, clients Clients, namespace string, diskName string, isLastBlockDevice bool) {
	pvcProvider := &PVCProvider{}
	pvProvider := &PVProvider{}

	pvcs, err := pvcProvider.GetSystemResources(ctx, clients, namespace, diskName)
	hasPVC := err == nil && len(pvcs) > 0

	pvs, err := pvProvider.GetSystemResources(ctx, clients, namespace, diskName)
	hasPV := err == nil && len(pvs) > 0

	if hasPVC {
		r.display.ShowNestedSystemResource(pvcProvider.GetDisplayIcon(), "PVC", pvcs[0].GetDisplayInfo(), pvcs[0].GetPhase(), !hasPV && isLastBlockDevice)
	}

	if hasPV {
		r.display.ShowDeepNestedSystemResource(pvProvider.GetDisplayIcon(), "PV", pvs[0].GetDisplayInfo(), pvs[0].GetPhase(), isLastBlockDevice)
	}
}

func (r *VMCommandRunner) getBlockDevicePhase(ctx context.Context, clients Clients, namespace, name, kind string) (string, error) {
	var gvr schema.GroupVersionResource
	switch kind {
	case "VirtualDisk", "VirtualImage":
		gvr = schema.GroupVersionResource{Group: "virtualization.deckhouse.io", Version: "v1alpha2", Resource: strings.ToLower(kind) + "s"}
		res, err := clients.GetDynamicClient().Resource(gvr).Namespace(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return "", err
		}
		return nestedString(res.Object, "status", "phase"), nil
	case "ClusterVirtualImage":
		gvr = schema.GroupVersionResource{Group: "virtualization.deckhouse.io", Version: "v1alpha2", Resource: "clustervirtualimages"}
		res, err := clients.GetDynamicClient().Resource(gvr).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return "", err
		}
		return nestedString(res.Object, "status", "phase"), nil
	default:
		return "", fmt.Errorf("unsupported block device kind: %s", kind)
	}
}

// VD command runner with system resources
type VDCommandRunner struct {
	BaseCommandRunner
	showSystemResources bool
}

func (r *VDCommandRunner) Run(ctx context.Context, clients Clients, namespace string, resourceName string) error {
	resources, err := r.provider.GetResources(ctx, clients, namespace)
	if err != nil {
		return fmt.Errorf("failed to get %s in %s: %w", r.provider.GetResourceType(), namespace, err)
	}

	if len(resources) == 0 {
		return nil
	}

	// Filter disks if a specific disk name is provided
	if resourceName != "" {
		resources = r.filterResourcesByName(resources, resourceName)
		if len(resources) == 0 {
			return fmt.Errorf("no %s named %s found in namespace %s", r.provider.GetResourceType(), resourceName, namespace)
		}
	}

	r.display.ShowNamespace(namespace)
	r.display.ShowResourceGroup(r.provider.GetDisplayIcon(), r.provider.GetResourceType()+"s")

	for _, resource := range resources {
		fmt.Printf("    ╰- %s : %s\n", resource.GetDisplayInfo(), r.display.ShowPhase(resource.GetPhase()))

		if r.showSystemResources {
			r.showStorageResourcesForDisk(ctx, clients, namespace, resource.GetName())
		}
	}

	return nil
}

func (r *VDCommandRunner) showStorageResourcesForDisk(ctx context.Context, clients Clients, namespace string, diskName string) {
	pvcProvider := &PVCProvider{}
	pvProvider := &PVProvider{}

	pvcs, err := pvcProvider.GetSystemResources(ctx, clients, namespace, diskName)
	hasPVC := err == nil && len(pvcs) > 0

	pvs, err := pvProvider.GetSystemResources(ctx, clients, namespace, diskName)
	hasPV := err == nil && len(pvs) > 0

	if hasPVC {
		r.display.ShowNestedSystemResource(pvcProvider.GetDisplayIcon(), "PVC", pvcs[0].GetDisplayInfo(), pvcs[0].GetPhase(), !hasPV)
	}

	if hasPV {
		r.display.ShowDeepNestedSystemResource(pvProvider.GetDisplayIcon(), "PV", pvs[0].GetDisplayInfo(), pvs[0].GetPhase(), true)
	}
}

// Global variables
var (
	configFlags         = genericclioptions.NewConfigFlags(true)
	allNamespaces       bool
	vmName              string
	diskName            string
	showSystemResources bool

	rootCmd = &cobra.Command{
		Use:   "v12n",
		Short: "Deckhouse Virtualization Platform management tool",
		Long: `A kubectl plugin for managing Deckhouse Virtualization Platform resources.

This tool provides commands to view and manage VirtualMachines, Pods, BlockDevices, PVCs, and PVs.`,
	}

	getCmd = &cobra.Command{
		Use:   "get",
		Short: "Display information about resources",
		Long:  `Display information about VirtualMachines, VirtualDisks and related resources.`,
	}

	vmCmd = &cobra.Command{
		Use:   "vm [vm-name] [flags]",
		Short: "Display information about VirtualMachines in Deckhouse Virtualization Platform",
		Long: `Display hierarchical information about VirtualMachines, Pods, BlockDevices, PVCs, and PVs in one or all namespaces.

Examples:
  # Show info for the current namespace (without system resources)
  v12n get vm

  # Show info for the current namespace with pods, PVCs, and PVs
  v12n get vm -S

  # Show info for a specific namespace
  v12n get vm --namespace my-ns

  # Show info for a specific VM in the current namespace
  v12n get vm my-vm

  # Show info for a specific VM with system resources
  v12n get vm my-vm -S --namespace my-ns

  # Show info for all namespaces (without system resources)
  v12n get vm --all-namespaces`,
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
		RunE: runVM,
	}

	vdCmd = &cobra.Command{
		Use:   "vd [disk-name] [flags]",
		Short: "Display information about VirtualDisks",
		Long: `Display information about VirtualDisk resources.

Examples:
  # Show all VirtualDisks in the current namespace
  v12n get vd

  # Show all VirtualDisks with system resources (PVCs, PVs)
  v12n get vd -S

  # Show VirtualDisks in a specific namespace
  v12n get vd --namespace my-ns

  # Show a specific VirtualDisk in the current namespace
  v12n get vd my-disk

  # Show a specific VirtualDisk with system resources
  v12n get vd my-disk -S --namespace my-ns

  # Show VirtualDisks in all namespaces
  v12n get vd --all-namespaces`,
		Args: cobra.MaximumNArgs(1),
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				diskName = args[0]
			}
			if allNamespaces && diskName != "" {
				return fmt.Errorf("cannot use --all-namespaces with a specific disk name")
			}
			return nil
		},
		RunE: runVD,
	}
)

func init() {
	configFlags.AddFlags(rootCmd.PersistentFlags())
	vmCmd.Flags().BoolVarP(&allNamespaces, "all-namespaces", "A", allNamespaces, "If true, show information for all namespaces")
	vmCmd.Flags().StringVar(&vmName, "vm-name", "", "Name of a specific VirtualMachine to display")
	vmCmd.Flags().BoolVarP(&showSystemResources, "show-system-resources", "S", false, "If true, include system resources (pods, PVCs, PVs) in output")

	vdCmd.Flags().BoolVarP(&allNamespaces, "all-namespaces", "A", allNamespaces, "If true, show information for all namespaces")
	vdCmd.Flags().StringVar(&diskName, "disk-name", "", "Name of a specific VirtualDisk to display")
	vdCmd.Flags().BoolVarP(&showSystemResources, "show-system-resources", "S", false, "If true, include system resources (PVCs, PVs) in output")

	getCmd.AddCommand(vmCmd)
	getCmd.AddCommand(vdCmd)
	rootCmd.AddCommand(getCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// Generic command runner function
func runCommand(runner CommandRunner, resourceName string) error {
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

	clients := &KubernetesClients{
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
			if err := runner.Run(ctx, clients, ns.Name, resourceName); err != nil {
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
		if err := runner.Run(ctx, clients, namespace, resourceName); err != nil {
			return err
		}
	}
	return nil
}

func runVM(cmd *cobra.Command, args []string) error {
	display := &DisplayService{}
	provider := &VMProvider{}
	runner := &VMCommandRunner{
		BaseCommandRunner: BaseCommandRunner{
			provider: provider,
			display:  display,
		},
		showSystemResources: showSystemResources,
	}
	return runCommand(runner, vmName)
}

func runVD(cmd *cobra.Command, args []string) error {
	display := &DisplayService{}
	provider := &VDProvider{}
	runner := &VDCommandRunner{
		BaseCommandRunner: BaseCommandRunner{
			provider: provider,
			display:  display,
		},
		showSystemResources: showSystemResources,
	}
	return runCommand(runner, diskName)
}

// Utility function
func nestedString(obj map[string]interface{}, keys ...string) string {
	val, found, _ := unstructured.NestedString(obj, keys...)
	if !found {
		return ""
	}
	return val
}
