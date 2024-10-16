To edit a Runbook in Azure Automation and append a PowerShell script to retrieve credentials, follow these steps:

### Step-by-Step Guide

1. **Access the Azure Portal:**
    
    - Log in to the [Azure Portal](https://portal.azure.com/).
2. **Navigate to Your Automation Account:**
    
    - In the left sidebar, select **"All services"** and search for **"Automation Accounts."**
    - Click on your automation account, in this case, **"automation-dev."**
3. **Locate the Runbook:**
    
    - Within the Automation Account, find and click on **"Runbooks"** in the left menu.
    - Choose the Runbook you want to edit (e.g., **"Schedule-VMStartStop"**).
4. **Edit the Runbook:**
    
    - Click on **"Edit"** to open the Runbook editor.
    - If the Runbook is already published, you may need to click on **"Draft"** to make edits.
5. **Append the PowerShell Script:**
    
    - Scroll to the appropriate section of the Runbook where you want to append the code.
    - Insert the following code snippet to retrieve the credentials:
    
```powershell
$cred = Get-AutomationPSCredential -Name "automate-default"
$username = $cred.GetNetworkCredential().UserName
$password = $cred.GetNetworkCredential().Password

# Output the credentials (for testing, not recommended in production)
# Remove the below snippet in production
Write-Output "Username: $username"
Write-Output "Password: $password"
```


Ensure you replace `"automate-default"` with the actual name of the credential you wish to retrieve. You can get this information following this [ToC](https://secfortress.com/hacking/unmask_privileged_access_in_azure/#credential-security-in-automation-accounts) session of my blog.


1. **Save and Test the Runbook:**
    
    - After adding the script, click **"Save"**.
    - You can **Test the Runbook** by clicking on **"Test"** to validate that your changes work as expected.
    - Ensure you **publish** the Runbook after testing it to make the changes effective.
7. **Run the Runbook:**
    
    - Once published, you can run the Runbook, and it will execute the appended script, allowing you to see the output of the username and password (if applicable).

### Important Notes

- **Permissions:** Ensure you have the necessary permissions to edit the Runbook. If you have only `Reader` access, you will need to request elevated permissions from your administrator.
- **Security Considerations:** Be cautious about outputting credentials in logs or console output. It's a best practice to handle credentials securely and avoid exposing sensitive information.

### Additional Resources

For more detailed instructions, you can refer to the official Azure documentation on [creating and managing Runbooks](https://learn.microsoft.com/en-us/azure/automation/automation-runbook-types) and [Azure Automation best practices](https://learn.microsoft.com/en-us/azure/automation/automation-best-practices).
