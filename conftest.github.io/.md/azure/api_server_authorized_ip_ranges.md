## AKS API server does not define authorized IP ranges

The API server is the central way to interact with and manage a cluster. To improve cluster security and minimize attacks, the API server should only be accessible from a limited set of IP address ranges.

**Rego Policy:**

```rego
package main
    import future.keywords.in
    import future.keywords.every
    
    deny[msg] {
      some i
      aztype := input.resource_changes[i].type
      name := input.resource_changes[i].name
      guide := "http://myguide.com"
      aztype == "azurerm_kubernetes_cluster"
      is_null(input.resource_changes[i].change.after.api_server_authorized_ip_ranges)
      message := "AKS API server does not define authorized IP ranges, 'api_server_authorized_ip_ranges' must not be set to 'null'"
      msg := sprintf("\n\tResource:azurerm_kubernetes_cluster\n\t Resource name:%s\n\tMessage:%s.\n\tGuide:%s",[name,message,guide])
    }
    
    deny[msg] {
        some i
        aztype := input.resource_changes[i].type
      name := input.resource_changes[i].name
      guide := "http://myguide.com"
        aztype == "azurerm_kubernetes_cluster"
        count(input.resource_changes[i].change.after.api_server_authorized_ip_ranges)==0
        message := "AKS API server does not define authorized IP ranges, 'api_server_authorized_ip_ranges' must not be set to '[]'"
      msg := sprintf("\n\tResource:azurerm_kubernetes_cluster\n\t Resource name:%s\n\tMessage:%s.\n\tGuide:%s",[name,message,guide])
    }
    
    deny[msg]{
        authorized_ip:=["198.51.100.0/25"]
        name := input.resource_changes[i].name
        guide := "http://myguide.com"
        input_ips := input.resource_changes[i].change.after.api_server_authorized_ip_ranges
        my_set := {x | x := authorized_ip[_]}
        wrong_ips := [ ip | ip := input_ips[_]; not (ip in  my_set) ]
        count(wrong_ips) > 0
        message := "AKS API server does not define authorized IP ranges, 'api_server_authorized_ip_ranges' received wromg ip list "
        msg := sprintf("\n\tResource:azurerm_kubernetes_cluster\n\t Resource name:%s\n\tMessage:%s `%s`.\n\tGuide:%s",[name,message,wrong_ips,guide])
    
    }
```

**Terraform code for testing the Policy:**

```tf
resource "azurerm_kubernetes_cluster" "aks_cluster" {
        name                = "${azurerm_resource_group.aks_rg.name}-cluster"
        location            = azurerm_resource_group.aks_rg.location
        resource_group_name = azurerm_resource_group.aks_rg.name

        api_server_authorized_ip_ranges=["198.51.100.0/24"] #This setting violates the policy
    }

    OR
    
resource "azurerm_kubernetes_cluster" "aks_cluster" {
        name                = "${azurerm_resource_group.aks_rg.name}-cluster"
        location            = azurerm_resource_group.aks_rg.location
        resource_group_name = azurerm_resource_group.aks_rg.name

        api_server_authorized_ip_ranges=[] #This setting violates the policy
    }
```

**Policy Violation Example:**

```bash
   C:\conftest-terraform\az-k8s>conftest test output.json -p ../conftest/api_server_authorized_ip_ranges.rego 
    FAIL - output.json - main -
    Resource:azurerm_kubernetes_cluster
     Resource name:aks_cluster
    Message:AKS API server does not define authorized IP ranges, 'api_server_authorized_ip_ranges' received wromg ip list  `["198.51.100.0/24"]`.
    Guide:http://myguide.com

    3 tests, 2 passed, 0 warnings, 1 failure, 0 exceptions
  
  ```

**Remediation:**

`api_server_authorized_ip_ranges` must be set to list of white listed ips

An example terraform code which violates the policy is given below along with remediation:

```terraform
resource "azurerm_kubernetes_cluster" "aks_cluster" {
    name                = "${azurerm_resource_group.aks_rg.name}-cluster"
    location            = azurerm_resource_group.aks_rg.location
    resource_group_name = azurerm_resource_group.aks_rg.name
    api_server_authorized_ip_ranges=["198.51.100.0/24"] #This resolves the policy violation
}
```
---