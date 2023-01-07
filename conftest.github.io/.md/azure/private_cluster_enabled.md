## Ensure AKS enables private clusters

Enable the private cluster feature for your Azure Kubernetes Service cluster to ensure network traffic between your API server and your node pools remains on the private network only. This is a common requirement in many regulatory and industry compliance standards.

**Rego Policy:**

```rego
  package main

    deny[msg] {
    some i
    enabled := input.resource_changes[i].change.after.private_cluster_enabled
    aztype := input.resource_changes[i].type
    name := input.resource_changes[i].name
    guide := "http://myguide.com"
    aztype == "azurerm_kubernetes_cluster"
    enabled!=true
    message := "AKS is not enabled for private clusters, 'private_cluster_enabled' must not be equal to 'false'"
    msg := sprintf("\n\tResource:azurerm_kubernetes_cluster\n\t Resource name:%s\n\tMessage:%s.\n\tGuide:%s",[name,message,guide])
    }
```

**Terraform code for testing the Policy:**

```tf
resource "azurerm_kubernetes_cluster" "aks_cluster" {
    name                = "${azurerm_resource_group.aks_rg.name}-cluster"
    location            = azurerm_resource_group.aks_rg.location
    resource_group_name = azurerm_resource_group.aks_rg.name

    private_cluster_enabled=false #This setting violates the policy
}
```

**Policy Violation Example:**

```bash
   C:\conftest-terraform\az-k8s>conftest test output.json -p ../conftest/private_cluster_enabled.rego
    FAIL - output.json - main - 
        Resource:azurerm_kubernetes_cluster
         Resource name:aks_cluster
        Message:AKS is not enabled for private clusters, 'private_cluster_enabled' must not be equal to 'false'.
        Guide:http://myguide.com

    1 test, 0 passed, 0 warnings, 1 failure, 0 exceptions
 
  ```

**Remediation:**

`private_cluster_enabled` must be set to `true`

An example terraform code which violates the policy is given below along with remediation:

```terraform
resource "azurerm_kubernetes_cluster" "aks_cluster" {
    name                = "${azurerm_resource_group.aks_rg.name}-cluster"
    location            = azurerm_resource_group.aks_rg.location
    resource_group_name = azurerm_resource_group.aks_rg.name

    private_cluster_enabled=true #This resolves the policy violation
}
```
---