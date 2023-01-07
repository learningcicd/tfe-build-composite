## Ensure AKS cluster has Network Policy configured

he Kubernetes object type NetworkPolicy should be defined to have opportunity allow or block traffic to pods, as in a Kubernetes cluster configured with default settings, all pods can discover and communicate with each other without any restrictions.

**Rego Policy:**

```rego
    package main

    has_field(obj, field) {
        obj[field]
    }
    
    deny[msg] {
        some i,j
        aztype := input.resource_changes[i].type
        network_profile:=input.resource_changes[i].change.after.network_profile[j]
        name := input.resource_changes[i].name
          guide := "http://myguide.com"
        aztype == "azurerm_kubernetes_cluster"
        not has_field(network_profile, "network_policy")
        message := "AKS cluster network policies are not enforced, 'network_profile.network_policy' must not be empty"
          msg := sprintf("\n\tResource:azurerm_kubernetes_cluster\n\t Resource name:%s\n\tMessage:%s.\n\tGuide:%s",[name,message,guide])
    }  
```

**Terraform code for testing the Policy:**

```tf
resource "azurerm_kubernetes_cluster" "aks_cluster" {
    name                = "${azurerm_resource_group.aks_rg.name}-cluster"
    location            = azurerm_resource_group.aks_rg.location
    resource_group_name = azurerm_resource_group.aks_rg.name

    network_profile {
        network_plugin = "azure"
        load_balancer_sku = "standard"
        #POLICY : network_profile_network_policy 
        #network_policy="azure"  #If network_profile block missing the network_policy property, it violates the policy
        }
}
```

**Policy Violation Example:**

```bash
  C:\conftest-terraform\az-k8s>conftest test output.json -p ../conftest/network_profile_network_policy.rego
    FAIL - output.json - main - 
        Resource:azurerm_kubernetes_cluster
        Resource name:aks_cluster
        Message:AKS cluster network policies are not enforced, 'network_profile' block should not miss the 'network_policy' field.
        Guide:http://myguide.com

    1 test, 0 passed, 0 warnings, 1 failure, 0 exceptions
   
  ```

**Remediation:**

`network_profile` block should not miss the `network_policy` field

An example terraform code which violates the policy is given below along with remediation:

```terraform
   resource "azurerm_kubernetes_cluster" "aks_cluster" {
        name                = "${azurerm_resource_group.aks_rg.name}-cluster"
        location            = azurerm_resource_group.aks_rg.location
        resource_group_name = azurerm_resource_group.aks_rg.name

        network_profile {
            network_plugin = "azure"
            load_balancer_sku = "standard"
            #POLICY : network_profile_network_policy 
            network_policy="azure"  # This resolves the policy violation
          }
    }
```
---