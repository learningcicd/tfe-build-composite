## Ensure that Cloud Storage buckets have uniform bucket-level access enabled

When you enable uniform bucket-level access on a bucket, Access Control Lists (ACLs) are disabled, and only bucket-level Identity and Access Management (IAM) permissions grant access to that bucket and the objects it contains. You revoke all access granted by object ACLs and the ability to administrate permissions using bucket ACLs

**Rego Policy:**

```rego
package main
    import future.keywords.in
    has_field(obj, field) {
        obj[field] != null
    }
    
    deny[msg] {
        
        some i
        type := input.resource_changes[i].type
        after := input.resource_changes[i].change.after
        type == "google_storage_bucket"
        has_field(after, "uniform_bucket_level_access")
        not after.uniform_bucket_level_access
        name := input.resource_changes[i].name
        guide := "http://myguide.com"
        message := "Ensure that uniform bucket-level access is enabled for the storage bucket,'uniform_bucket_level_access' must not be set to 'false'"
        msg := sprintf("\n\tResource: google_storage_bucket\n\tResource name: %s\n\tMessage: %s\n\tGuide: %s", [name, message, guide])
    }
```

**Terraform code for testing the Policy:**

```tf
 resource "google_storage_bucket" "default" {
        name          = "no-public-access-bucket"
        location      = "US"
        force_destroy = true
        uniform_bucket_level_access = false #This violates the policy
    }
```

**Policy Violation Example:**

```bash
    C:\conftest-terraform\gcloud-sql-instance>conftest test output.json -p ../conftest/gcloud_enable_ubla.rego 
    FAIL - output.json - main - 
        Resource: google_storage_bucket
        Resource name: default
        Message: Ensure that uniform bucket-level access is enabled for the storage bucket,'uniform_bucket_level_access' must not be set to 'false'
        Guide: http://myguide.com

    1 test, 0 passed, 0 warnings, 1 failure, 0 exceptions
      
  ```

**Remediation:**

`uniform_bucket_level_access` must be set to `true`.

An example terraform code which violates the policy is given below along with remediation:

```terraform
resource "google_storage_bucket" "default" {
    name          = "no-public-access-bucket"
    location      = "US"
    force_destroy = true
    uniform_bucket_level_access = true #This resolves the violation of rego policy
    }
```
---