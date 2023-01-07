## Ensure VM serial port access disabled

An interactive serial port is rarely required, and an attack vector to gain access.   

**Rego Policy:**

```rego
package main
    import future.keywords.in


    has_field(obj, field) {
        obj[field]
    }

    # Deny if an IAM policy binding is not from an allowed domain
    deny[msg] {
        # Iterate over the resource changes
        some i
        type := input.resource_changes[i].type
        # Check if the resource is an IAM policy binding
        type == "google_compute_instance" 
        # Check if the compute instance has metadata
        instance_has_metadata := has_field(input.resource_changes[i].change.after, "metadata")
        # If it has metadata
        instance_has_metadata
        enable := upper(input.resource_changes[i].change.after.metadata["serial-port-enable"])
        enable == "TRUE"
        
        # Set the message for the denial
        name := input.resource_changes[i].name
        guide := "http://myguide.com"
        message := "Ensure 'metadata.serial-port-enable' must not be set to 'true'"
        msg := sprintf("\n\tResource: %s\n\tResource name: %s\n\tMessage: %s\n\tGuide: %s", [type, name, message, guide])
    }
```

**Terraform code for testing the Policy:**

```tf
resource "google_compute_instance" "vm" {
        name         = "my-vm"
        machine_type = "f1-micro"
        #zone         = "<your-vm-zone>"
        metadata ={
            serial-port-enable = true #This Violates the policy
            
        }
        boot_disk {
            initialize_params {
            image = "debian-cloud/debian-9"
            }
        }
        
        network_interface {
            network = "default"
        
            access_config {
            
            
            }
        }
    } 
```

**Policy Violation Example:**

```bash
C:\conftest-terraform\gcloud-sql-instance>conftest test output.json -p ../conftest/gcloud_disable_VM_serial_port_access.rego
    FAIL - output.json - main - 
        Resource: google_compute_instance
        Resource name: vm
        Message: Ensure 'metadata.serial-port-enable' must not be set to 'true'
        Guide: http://myguide.com

    1 test, 0 passed, 0 warnings, 1 failure, 0 exceptions
```

**Remediation:**

Ensure `metadata.serial-port-enable` must not be set to 'true'

An example terraform code which violates the policy is given below along with remediation:

```terraform
resource "google_compute_instance" "vm" {
        name         = "my-vm"
        machine_type = "f1-micro"
        #zone         = "<your-vm-zone>"
        metadata ={
            serial-port-enable = false #This resolves the policy violation
            
        }
        boot_disk {
            initialize_params {
            image = "debian-cloud/debian-9"
            }
        }
        
        network_interface {
            network = "default"
        
            access_config {
            
            
            }
        }
    }   
```

---