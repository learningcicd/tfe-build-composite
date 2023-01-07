## Ensure AKS uses Azure policies

Azure Policy for Kubernetes service (AKS) extends Gatekeeper v3, an admission controller webhook for Open Policy Agent (OPA), to apply at-scale enforcements and safeguards on your clusters in a centralized, consistent manner.

**Rego Policy:**

```rego
package main
    deny[msg] {
      some i
      aztype := input.resource_changes[i].type
      name := input.resource_changes[i].name
      guide := "http://myguide.com"
      aztype == "azurerm_kubernetes_cluster"
      is_null(input.resource_changes[i].change.after.azure_policy_enabled)
      message := "AKS does not use Azure policies, 'azure_policy_enabled' must not be set to 'null'"
      msg := sprintf("\n\tResource:azurerm_kubernetes_cluster\n\t Resource name:%s\n\tMessage:%s.\n\tGuide:%s",[name,message,guide])
      
    }
```

**Terraform code for testing the Policy:**

```tf
resource "azurerm_kubernetes_cluster" "aks_cluster" {
    name                = "${azurerm_resource_group.aks_rg.name}-cluster"
    location            = azurerm_resource_group.aks_rg.location
    resource_group_name = azurerm_resource_group.aks_rg.name

    azure_policy_enabled=false #This setting violates the policy
}
```

**Policy Violation Example:**

```bash
C:\conftest-terraform\az-k8s>conftest test output.json -p ../conftest/azure_policy_enabled.rego
    FAIL - output.json - main - 
        Resource:azurerm_kubernetes_cluster
        Resource name:aks_cluster
        Message:AKS does not use Azure policies, 'azure_policy_enabled' must not be set to 'false'.
        Guide:http://myguide.com

    1 test, 0 passed, 0 warnings, 1 failure, 0 exceptions
  
  ```

**Remediation:**

`azure_policy_enabled` must be set to 'true'

An example terraform code which violates the policy is given below along with remediation:

```terraform
resource "azurerm_kubernetes_cluster" "aks_cluster" {
    name                = "${azurerm_resource_group.aks_rg.name}-cluster"
    location            = azurerm_resource_group.aks_rg.location
    resource_group_name = azurerm_resource_group.aks_rg.name

    azure_policy_enabled=true #This resolves the policy violation
}
```
---