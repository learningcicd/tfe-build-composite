## Ensure that Cloud SQL Database Instances are not publicly exposed

Database instances should be configured so that they are not available over the public internet, but to internal compute resources which access them.

**Rego Policy:**

```rego
    package main

    has_field(obj, field) {
        obj[field]
    }

    deny[msg] {
        some i, j, k
        type := input.resource_changes[i].type
        ip_configuration := input.resource_changes[i].change.after.settings[j].ip_configuration[k]
        name := input.resource_changes[i].name
        guide := "http://myguide.com"
        type == "google_sql_database_instance"
        has_field(ip_configuration, "ipv4_enabled")
        ip_configuration.ipv4_enabled == true
        message := "Remove public access from database instances, 'ip_configuration.ipv4_enabled' should not be set to 'true'"
        msg := sprintf("\n\tResource:google_sql_database_instance\n\t Resource name:%s\n\tMessage:%s.\n\tGuide:%s", [name, message, guide])
    }

    deny[msg] {
        public_ip := "0.0.0.0/0"
        some i, j, k, l
        type := input.resource_changes[i].type
        ip_configuration := input.resource_changes[i].change.after.settings[j].ip_configuration[k]
        type == "google_sql_database_instance"
        has_field(ip_configuration, "authorized_networks")
        authorized_networks := ip_configuration.authorized_networks[l].value
        authorized_networks == public_ip
        name := input.resource_changes[i].name
        guide := "http://myguide.com"
        message := "Remove public access from database instances, 'ip_configuration.authorized_networks' must not have ip range '0.0.0.0/0'"
        msg := sprintf("\n\tResource:google_sql_database_instance\n\t Resource name:%s\n\tMessage:%s.\n\tGuide:%s", [name, message, guide])
    }
```

**Terraform code for testing the Policy:**

```tf
resource "google_sql_database_instance" "mysql_public_ip_instance_name" {
        database_version = "MYSQL_5_7"
        name             = "mysql-public-ip-instance-name"
        region           = "asia-southeast2"
        settings {
          availability_type = "ZONAL"
          disk_size         = 100
          disk_type         = "PD_SSD"
          ip_configuration {
            # Add optional authorized networks
            # Update to match the customer's networks
            authorized_networks {
              name  = "test-net-3"
              value = "203.0.113.0/24"
            }
            # Enable public IP
            ipv4_enabled = true #This setting violates the policy
          }
          tier = "db-custom-4-26624"
        }
        deletion_protection = false 
      }

    OR
    
    resource "google_sql_database_instance" "mysql_public_ip_instance_name" {
        database_version = "MYSQL_5_7"
        name             = "mysql-public-ip-instance-name"
        region           = "asia-southeast2"
        settings {
          availability_type = "ZONAL"
          disk_size         = 100
          disk_type         = "PD_SSD"
          ip_configuration {
            # Add optional authorized networks
            # Update to match the customer's networks
            authorized_networks {
              name  = "test-net-3"
              value = "203.0.113.0/24"
            }
            authorized_networks {
              name  = "public"
              value = "0.0.0.0/0" #This ip violates the allow public access policy
            }
            # Enable public IP
            ipv4_enabled = false
          }
          tier = "db-custom-4-26624"
        }
        deletion_protection = false 
      }
```

**Policy Violation Example:**

```bash
 C:\conftest-terraform\gcloud-sql-instance>conftest test output.json -p ../conftest/sql_no_public_access.rego 
    FAIL - output.json - main - 
        Resource:google_sql_database_instance
         Resource name:mysql_public_ip_instance_name
        Message:Remove public access from database instances, 'ip_configuration.authorized_networks' must not have ip range '0.0.0.0/0'.
        Guide:http://myguide.com
    FAIL - output.json - main -
        Resource:google_sql_database_instance
         Resource name:mysql_public_ip_instance_name
        Message:Remove public access from database instances, 'ip_configuration.ipv4_enabled' should not be set to 'true'.
        Guide:http://myguide.com
  ```

**Remediation:**

`ip_configuration.ipv4_enabled` must be set to `false`

An example terraform code which violates the policy is given below along with remediation:

```terraform
resource "google_sql_database_instance" "mysql_public_ip_instance_name" {
        database_version = "MYSQL_5_7"
        name             = "mysql-public-ip-instance-name"
        region           = "asia-southeast2"
        settings {
          availability_type = "ZONAL"
          disk_size         = 100
          disk_type         = "PD_SSD"
          ip_configuration {
            # Add optional authorized networks
            # Update to match the customer's networks
            authorized_networks {
              name  = "test-net-3"
              value = "203.0.113.0/24"
            }
            # Enable public IP
            ipv4_enabled = false #This resolves the public access from database instances
          }
          tier = "db-custom-4-26624"
        }
        deletion_protection = false 
    }
```
`ip_configuration.authorized_networks` must not have ip range `0.0.0.0/0`
```
resource "google_sql_database_instance" "mysql_public_ip_instance_name" {
        database_version = "MYSQL_5_7"
        name             = "mysql-public-ip-instance-name"
        region           = "asia-southeast2"
        settings {
          availability_type = "ZONAL"
          disk_size         = 100
          disk_type         = "PD_SSD"
          ip_configuration {
            # Add optional authorized networks
            # Update to match the customer's networks
            authorized_networks {
              name  = "test-net-3"
              value = "203.0.113.0/24"
            }
            ipv4_enabled = false 
          }
          tier = "db-custom-4-26624"
        }
        deletion_protection = false 
    }
```
---