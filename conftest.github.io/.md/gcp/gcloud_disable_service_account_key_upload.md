## Ensure service account key upload is disabled

Another way to use user-managed keys is to create them locally and upload them to Cloud 

**Rego Policy:**

```rego
package main

    # Deny the creation of service account keys
    deny[msg] {
        some i
        type := input.resource_changes[i].type
        type == "google_service_account_key"
        not input.resource_changes[i].after.public_key_data
        name := input.resource_changes[i].name
        guide := "http://myguide.com"
        message := "Service account key upload is not allowed"
        msg := sprintf("\n\tResource:google_service_account_key\n\t Resource name:%s\n\tMessage:%s.\n\tGuide:%s", [name, message, guide])
    } 
```

**Terraform code for testing the Policy:**

```tf
resource "google_service_account" "myaccount" {
        account_id   = "myaccount"
        display_name = "My Service Account"
}
     
resource "google_service_account_key" "mykey" {
service_account_id = google_service_account.myaccount.name
public_key_type    = "TYPE_X509_PEM_FILE"
public_key_data = file("./githubPublicKey") #This  violates the policy
}
```

**Policy Violation Example:**

```bash
 C:\conftest-terraform\gcloud-sql-instance>conftest test output.json -p ../conftest/gcloud_disable_service_account_key_upload.rego
    FAIL - output.json - main - 
        Resource:google_service_account_key
        Resource name:mykey
        Message:Service account key upload is not allowed..
        Guide:http://myguide.com

    1 test, 0 passed, 0 warnings, 1 failure, 0 exceptions
      
  ```

**Remediation:**

`public_key_data` must not to be set to public key data.

An example terraform code which violates the policy is given below along with remediation:

```terraform
resource "google_service_account" "myaccount" {
    account_id   = "myaccount"
    display_name = "My Service Account"
}

resource "google_service_account_key" "mykey" {
    service_account_id = google_service_account.myaccount.name
    public_key_type    = "TYPE_X509_PEM_FILE"
    public_key_data = null  #This  resolves the  policy violates
}
```

---