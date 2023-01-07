## Ensure service account key creation is disabled

Service account keys represent a big responsibility and security risk, and you should employ Google-managed keys as much as possible. 

**Rego Policy:**

```rego
package main

    # Deny the creation of service account keys
    deny[msg] {
        some i
        type := input.resource_changes[i].type
        type == "google_service_account_key"
        name := input.resource_changes[i].name
        guide := "http://myguide.com"
        message := "Service account key creation is not allowed. Please use an existing key or request a new one through the proper channels."
        msg := sprintf("\n\tResource:google_service_account_key\n\t Resource name:%s\n\tMessage:%s.\n\tGuide:%s", [name, message, guide])
    }  
```

**Terraform code for testing the Policy:**

```tf
resource "google_service_account" "myaccount" {
        account_id   = "myaccount"
        display_name = "My Service Account"
      }
      #This  "google_service_account_key"  resource block violates the policy
      resource "google_service_account_key" "mykey" {
        service_account_id = google_service_account.myaccount.name
        public_key_type    = "TYPE_X509_PEM_FILE"
      }
```

**Policy Violation Example:**

```bash
  C:\conftest-terraform\gcloud-sql-instance>conftest test output.json -p ../conftest/gcloud_disable_service_account_key_creation.rego 
    FAIL - output.json - main - 
        Resource:google_service_account_key
        Resource name:mykey
        Message:Service account key creation is not allowed. Please use an existing key or request a new one through the proper channels..    
        Guide:http://myguide.com

    1 test, 0 passed, 0 warnings, 1 failure, 0 exceptions
   
  ```

**Remediation:**

resource `google_service_account_key` must not to be used to create key.

An example terraform code which violates the policy is given below along with remediation:

```terraform
resource "google_service_account" "myaccount" {
    account_id   = "myaccount"
    display_name = "My Service Account"
    }
```

---