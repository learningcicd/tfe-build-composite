## Ensure that Cloud Storage bucket is not anonymously or publicly accessible

Using 'allUsers' or 'allAuthenticatedUsers' as members in an IAM member/binding causes data to be exposed outside of the organisation.

**Rego Policy:**

```rego
package main
    import future.keywords.in
    has_field(obj, field) {
        obj[field] != null
    }


    deny[msg] {
        deny_members:=["allUsers","allAuthenticatedUsers"]
        deny_set := { m | m := deny_members[_] }
        some i
        type := input.resource_changes[i].type
        input_members := input.resource_changes[i].change.after.members
        type == "google_storage_bucket_iam_binding"
        has_field(input.resource_changes[i].change.after, "members")    
        invalid_members := [ ip | ip := input_members[_]; (ip in deny_set) ]
        count(invalid_members) > 0
        name := input.resource_changes[i].name
        guide := "http://myguide.com"
        message := "Remove public access from storage bucket, 'allUsers' and 'allAuthenticatedUsers' are must not allowed in 'members'"
        msg := sprintf("\n\tResource: google_storage_bucket_iam_binding\n\tResource name: %s\n\tMessage: %s\n\tGuide: %s", [name, message, guide])
    }
```

**Terraform code for testing the Policy:**

```tf
resource "google_storage_bucket" "default" {
        name          = "no-public-access-bucket"
        location      = "US"
        force_destroy = true
        uniform_bucket_level_access = false
      }
      
      resource "google_storage_bucket_iam_binding" "binding" {
        bucket = google_storage_bucket.default.name
        role = "roles/storage.admin"
        members = [
          "allUsers", #This 'allUsers' member violates the policy
        ]
    }
```

**Policy Violation Example:**

```bash
 C:\conftest-terraform\gcloud-sql-instance>conftest test output.json -p ../conftest/gcloud_no_public_access.rego 
    FAIL - output.json - main - 
        Resource: google_storage_bucket_iam_binding
        Resource name: binding
        Message: Remove public access from storage bucket, 'allUsers' and 'allAuthenticatedUsers' are must not allowed in 'members'
        Guide: http://myguide.com

    1 test, 0 passed, 0 warnings, 1 failure, 0 exceptions
      
  ```

**Remediation:**

`members` must be set to authorized users.

An example terraform code which violates the policy is given below along with remediation:

```terraform
resource "google_storage_bucket" "default" {
        name          = "no-public-access-bucket"
        location      = "US"
        force_destroy = true
        uniform_bucket_level_access = false
      }
      
      resource "google_storage_bucket_iam_binding" "binding" {
        bucket = google_storage_bucket.default.name
        role = "roles/storage.admin"
        members = [
          "user:jane@example.com", #This resolves the policy violation
        ]
      }
```
---