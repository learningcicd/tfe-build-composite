## Enable automated backups to recover from data-loss

Automated backups are not enabled by default. Backups are an easy way to restore data in a corruption or data-loss scenario.

**Rego Policy:**

```rego
package main

    has_field(obj, field) {
        obj[field]
    }

    deny[msg] {
        some i, j, k
        type := input.resource_changes[i].type
        settings := input.resource_changes[i].change.after.settings[j]
        type == "google_sql_database_instance"
        has_field(settings, "backup_configuration")
        enabled := settings.backup_configuration[k].enabled
        not enabled
        name := input.resource_changes[i].name
        guide := "http://myguide.com"
        message := "No recovery of lost or corrupted data, 'settings.backup_configuration.enable' must not be set to 'false'"
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
          backup_configuration {
            enabled = false #This violates the sql backup policy
          }
          ip_configuration {
            # Add optional authorized networks
            # Update to match the customer's networks
            authorized_networks {
              name  = "test-net-3"
              value = "203.0.113.0/24"
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
 C:\conftest-terraform\gcloud-sql-instance>conftest test output.json -p ../conftest/gcloud_sql_enable_backup.rego
    FAIL - output.json - main -
        Resource:google_sql_database_instance
         Resource name:mysql_public_ip_instance_name
        Message:No recovery of lost or corrupted data, 'settings.backup_configuration.enable' must not be set to 'false'.
        Guide:http://myguide.com
  ```

**Remediation:**

`settings.backup_configuration.enable` must be set to `true`

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
        backup_configuration {
        enabled = true
        }
        ip_configuration {
        # Add optional authorized networks
        # Update to match the customer's networks
        authorized_networks {
            name  = "test-net-3"
            value = "203.0.113.0/24"
        }
        # Enable public IP
        ipv4_enabled = false 
        }
        tier = "db-custom-4-26624"
    }
    deletion_protection = false 
}
```

---