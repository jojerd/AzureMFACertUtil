# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.NOTES
	Name: AzureMFACertUtil.ps1
	Requires: PowerShell 5.1, a Global Admin (GA Account) for your Azure Tenant.
    Major Release History:
        12/15/2022 - Initial Release

.SYNOPSIS
Decodes the Azure Multi-Factor Auth Client Service Principals (certificates) into a human readable format. 

.DESCRIPTION
This utility will allow you to view, and remove certificates that are uploaded to the Azure Multi-Factor Auth Client Service.
Normally it lists the certificates encoded in Base64 format. This utility will provide the same data as default, but will include
other more human readable data so that decisions regarding the certificates can be made with a clear understanding of what the 
certificate belongs too.
Script does generate a log file for troubleshooting as well as logging actions that are taken.


.EXAMPLE
Can execute the script directly which will pull up a main menu for options on how you would like to proceed. 


#>
#Requires -Version 5.1
$Global:ProgressPreference = 'SilentlyContinue'
#Log filename
$Logname = 'AzureMFACertUtil.log'

# Special thanks to EE Matt Byrd for the Write-Log function
function Write-Log {
    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$String,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [switch]$OutHost,

        [switch]$OpenLog

    )

    begin {
        # Get our log file path
        $Path = Get-Location
        $LogFile = Join-Path $Path $Name
        if ($OpenLog) {
            Notepad.exe $LogFile
            exit
        }
    }
    process {

        # Get the current date
        [string]$date = Get-Date -Format G

        # Build output string
        [string]$logstring = ( "[" + $date + "] - " + $string)

        # Write everything to our log file and the screen
        $logstring | Out-File -FilePath $LogFile -Append -Confirm:$false
        if ($OutHost) { Write-Host $logstring }
        else { Write-Verbose  $logstring }
    }
}
function Get-MSOLServiceConnection {
    Write-Log -String "Checking if MSOL service is connected" -Name $Logname
    Get-MsolDomain -ErrorAction SilentlyContinue | Out-Null
    if ($?) {
        Write-Log -String "Already connected returning to function" -Name $Logname
        Return
    }
    else {
        try {
            Write-Log -String "Not connected to MSOL service, establishing a connection" -Name $Logname
            Connect-MsolService
            Write-Log -String "Connection establisted successfully, returning to function" -Name $Logname
            Return
        }
        catch {
            Write-Log -String "Unable to connect to MSOL Service" -Name $Logname
            Write-Log -String "Exception encountered $($_.Exception.Message)" -Name $Logname
            Write-Host "$($_.Exception.Message)"
            Write-Error "Unable to connect to Msol Service" -ErrorAction Stop
        }
    }
}

function Get-Confirmation {
    begin {
        write-log -String "Prompting user if they are sure they want to automatically remove all expired certificates" -Name $Logname
        Add-Type -AssemblyName PresentationCore, PresentationFramework
        $ConfirmButton = [System.Windows.MessageBoxButton]::YesNoCancel
        $ConfirmTitle = "Are you absolutely sure?"
        $ConfirmIcon = [System.Windows.MessageBoxImage]::Warning
        $Confirmbody = "The Azure MFA Service Principal Credentials may contain Certificates used with the Azure MFA Extension for NPS (Network Policy Server). Deleting these will break NPS services using the MFA extension."
    }

    process {
        $ConfirmResult = [System.Windows.MessageBox]::Show($Confirmbody, $ConfirmTitle, $ConfirmButton, $ConfirmIcon)

        if ($ConfirmResult -eq 'Yes') {
            Write-Log -String "$($ExecutingUser) selected Yes to confirm that all expired MFA Certificates will be deleted automatically" -Name $Logname
            Write-Log -String "Calling Remove-CertsAutomatic function" -Name $Logname
            Remove-CertsAutomatic
 
        }
        elseif ($ConfirmResult -eq 'No') {
            Write-Log -String "User selected No to remove certificates Automatically" -Name $Logname
            Write-Log -String "Calling Remove-CertsManual" -Name $Logname
            Remove-CertsManual
        }
        elseif ($Confirmresult -eq 'Cancel') {
            Write-Log -String "User selected cancel, exiting script" -Name $Logname
            Write-Host "Script completed, no changes have been made."
            Exit
        }
    }
    End {
        Write-Log -String "Ending Get-UserInput function" -Name $Logname
    }
    
}
function Remove-Certificates {
    begin {
        write-log -String "Prompting user if they would like to remove certificates manually or automatically" -Name $Logname
        Add-Type -AssemblyName PresentationCore, PresentationFramework
        $PopupButton = [System.Windows.MessageBoxButton]::YesNoCancel
        $PopupTitle = "Delete Certificates from Azure Multi-Factor Client Service?"
        $PopupIcon = [System.Windows.MessageBoxImage]::Question
        $Popupbody = "Do you want to remove expired certificates Automatically? (Yes = Automatic, No = Manually)"
    }

    process {
        $PopupResult = [System.Windows.MessageBox]::Show($Popupbody, $PopupTitle, $PopupButton, $PopupIcon)

        if ($PopupResult -eq 'Yes') {
            Write-Log -String "User selected Yes to remove expired MFA Certificates Automatically" -Name $Logname
            Write-Log -String "Calling Get-Confirmation function to confirm automatic expired certificate removal" -Name $Logname
            Get-Confirmation
 
        }
        elseif ($PopupResult -eq 'No') {
            Write-Log -String "User selected No to remove certificates Automatically" -Name $Logname
            Write-Log -String "Calling Remove-CertsManual" -Name $Logname
            Remove-CertsManual
        }
        elseif ($Popupresult -eq 'Cancel') {
            Write-Log -String "User selected cancel, exiting script" -Name $Logname
            Write-Host "Script completed, no changes have been made."
            Exit
        }
    }
    End {
        Write-Log -String "Ending Get-UserInput function" -Name $Logname
    }
    
    
}
function Get-UserFeedback {
    begin {
        write-log -String "Prompting user if they would like to delete additional certificates" -Name $Logname
        Add-Type -AssemblyName PresentationCore, PresentationFramework
        $Button = [System.Windows.MessageBoxButton]::YesNoCancel
        $Title = "Delete Certificates from Azure Multi-Factor Client Service?"
        $Icon = [System.Windows.MessageBoxImage]::Question
        $body = "Do you want to delete additonal certificates?"
    }

    process {
        $Result = [System.Windows.MessageBox]::Show($body, $Title, $Button, $Icon)

        if ($Result -eq 'Yes') {
            Write-Log -String "User selected Yes to delete additional certificates" -Name $Logname
            Write-Log -String "Calling Remove-CertsManual function" -Name $Logname
            Clear-Host
            Clear-Variable Cert, Certlist, CertDetails, CertObjectDetails
            Remove-CertsManual
 
        }
        elseif ($Result -eq 'No') {
            Write-Log -String "User selected No to remove additional certificates" -Name $Logname
            Write-Log -String "Ending script" -Name $Logname
            Clear-Host
            Write-Host ""
            Write-Host "Script completed, no additional certificates will be removed."
            Write-Host ""
            Read-Host -Prompt "Hit enter to exit"
            Exit
        }
        elseif ($Result -eq 'Cancel') {
            Write-Log -String "User selected cancel, exiting script" -Name $Logname
            Write-Host "Script completed, no changes have been made."
            Exit
        }
    }
    End {
        Write-Log -String "Ending Get-UserInput function" -Name $Logname
    }
    
}

function Remove-CertsManual {
    Get-MSOLServiceConnection
    Clear-Host
    $Certs = Get-MsolServicePrincipalCredential -AppPrincipalId 981f26a1-7f43-403b-a875-f8b09b8cd720 -ReturnKeyValues 1 | Where-Object { $null -ne $_.KeyId }
    if ($null -ne $Certs) {
        $Certlist = @()
        foreach ($Cert in $Certs) {
            $CertDetails = [System.Security.Cryptography.X509Certificates.X509Certificate2]([System.Convert]::FromBase64String($Cert.Value))
            $CertObjectDetails = New-Object PSObject -Property ([ordered]@{
                    Type       = $Cert.Type
                    Value      = $Cert.Value
                    KeyId      = $Cert.KeyId
                    Thumbprint = $CertDetails.Thumbprint
                    Subject    = $CertDetails.Subject
                    StartDate  = $CertDetails.NotBefore
                    EndDate    = $CertDetails.NotAfter
                    Usage      = $Validcred.Usage
                })
            $Certlist += $CertObjectDetails
        }
        Write-Output $Certlist
        Write-Log -String "Prompting user for KeyId of Certificate to removed" -Name $Logname
        $KeyId = Read-Host -Prompt "KeyId of Certificate to delete"
        Write-Log -String "User entered KeyId: $($KeyId)" -Name $Logname
        #$RemoveCert = Get-MsolServicePrincipalCredential -AppPrincipalId 981f26a1-7f43-403b-a875-f8b09b8cd720 -ReturnKeyValues 1 | Where-Object {$_.KeyId -like "$KeyId" }
        #Write-Log -String "$($RemoveCert.KeyId) returned from lookup" -Name $Logname
        Try {
            Write-Log -String "Attempting to delete certificate with KeyId of $($KeyId)" -Name $Logname
            Remove-MsolServicePrincipalCredential -AppPrincipalId 981f26a1-7f43-403b-a875-f8b09b8cd720 -KeyIds $KeyId
            Write-Log -String "Deleting Certificate KeyId $($KeyId)" -Name $Logname
            Write-Host "Certificate with KeyId: $($KeyId) has been deleted"
            Get-UserFeedback
        }
        catch {

            Write-Log -String "Encountered an Exception $($Exception.Message)" -Name $Logname
            Write-Host "$($Exception.Message)"
            Write-Error "Encountered an Exception, no certificates were removed" -ErrorAction SilentlyContinue
            Write-Host "Exception encountered, unable to continue" -ForegroundColor Red
            Read-Host -Prompt "Hit Enter to exit script, check log for exception details"
            Write-Log -String "Exiting script after exception encountered while attempting to remove certificate" -Name $Logname
            Exit
        }
            
        
    }


    else {
        Write-Log -String "No Certificates were found, nothing to delete" -Name $Logname
        Write-Host "No Certificates were found, nothing to delete"
        Read-Host -Prompt "Hit enter key to exit script"
        Exit
    }
    
}

function Remove-CertsAutomatic {
    Get-MSOLServiceConnection
    Clear-Host
    if ($ExpiredCreds.count -gt 0) {
        foreach ($ExpiredCert in $ExpiredCreds) {
            $ExpiredDetails = [System.Security.Cryptography.X509Certificates.X509Certificate2]([System.Convert]::FromBase64String($ExpiredCert.Value))
            Remove-MsolServicePrincipalCredential -AppPrincipalId 981f26a1-7f43-403b-a875-f8b09b8cd720 -KeyIds $ExpiredCert.KeyId
            Write-Log -String "Deleting certificate associated with KeyId: $($ExpiredCert.KeyId)" -Name $Logname
            Write-Host "Deleting certificate associated with KeyId: $($ExpiredCert.KeyId)"
            Write-Log -String "Thumbprint: $($ExpiredDetails.Thumbprint)" -Name $Logname
            Write-Host "Thumbprint: $($ExpiredDetails.Thumbprint)"
            Write-Log -String "Subjet: $($ExpiredDetails.Subject)" -Name $Logname
            Write-Host "Subjet: $($ExpiredDetails.Subject)"
            Write-Log -String "EndDate: $($ExpiredDetails.NotAfter)" -Name $Logname
            Write-Host "EndDate: $($ExpiredDetails.NotAfter)"
        }
        Write-Log -String "Deleted $($ExpiredCreds.count) expired certificates" -Name $Logname
        Write-Host "Deleted $($ExpiredCreds.count) expired certificates"
        Write-Host ""
        Read-Host -Prompt "Hit enter to exit the script"
        Write-Log -String "Exiting script" -Name $Logname
        Exit
    }
    else {
        Clear-Host
        Write-Log -String "No expired certificates to delete, nothing to do" -Name $Logname
        Write-Host "No certificates are expired, nothing to do"
        Write-Host "If you wish to delete certificates, recommendation would be to select Manually"
        Write-Host ""
        Read-Host -Prompt "Hit enter key to exit script"
        Write-Log -String "Exiting script" -Name $Logname
        Exit
    }
    
}

function Get-UserInput {
    begin {
        write-log -String "Prompting user if they would like to remove any certificates" -Name $Logname
        Add-Type -AssemblyName PresentationCore, PresentationFramework
        $PromptButton = [System.Windows.MessageBoxButton]::YesNoCancel
        $PromptPopupTitle = "Delete Certificates from Azure Multi-Factor Client Service?"
        $PromptPopupIcon = [System.Windows.MessageBoxImage]::Question
        $PromptPopupbody = "Did you want to remove any certificates from the MFA Client Service?"
    }

    process {
        $PromptPopupResult = [System.Windows.MessageBox]::Show($PromptPopupbody, $PromptPopupTitle, $PromptButton, $PromptPopupIcon)

        if ($PromptPopupResult -eq 'Yes') {
            Write-Log -String "User selected Yes to remove MFA Certificates" -Name $Logname
            Write-Log -String "Calling Remove-Certificates function" -Name $Logname
            Remove-Certificates
 
        }
        elseif ($PromptPopupResult -eq 'No') {
            Write-Log -String "User selected No to remove certificates question" -Name $Logname
            Write-Host "Script completed, no changes have been made."
            Exit
        }
        elseif ($PromptPopupresult -eq 'Cancel') {
            Write-Log -String "User selected cancel, exiting script" -Name $Logname
            Write-Host "Script completed, no changes have been made."
            Exit
        }
    }
    End {
        Write-Log -String "Ending Get-UserInput function" -Name $Logname
    }
}



#Get Current Certificates Function
function Get-CurrentCertificates {
    Write-Log -String "User selected to get current certificates" -Name $Logname
    Get-MSOLServiceConnection
    Write-Log -String "Pulling service principals" -Name $Logname
    $Credentials = Get-MsolServicePrincipalCredential -AppPrincipalId 981f26a1-7f43-403b-a875-f8b09b8cd720 -ReturnKeyValues 1 | Where-Object { $null -ne $_.KeyId }
    # Get current date for comparison with certificates that are retrieved to check for expired certs.
    $Date = Get-Date -Format "MM/dd/yyyy HH:mm:ss"
    # Certificate arrays for Valid and Expired certificates.
    $ExpiredCreds = @()
    $ValidCreds = @()
    Write-Log -String "Calling foreach loop to itenerate through details and separate valid certs from expired certs" -Name $Logname
    foreach ($Cred in $Credentials) {
        if ($Cred.EndDate -lt $Date) { $ExpiredCreds += $Cred }else { $ValidCreds += $Cred }
    }
    Write-Log -String "Calling foreach loop to decode Base64 and provide details for valid certificates" -Name $Logname
    # Array for storing valid certificates in memory to present to user after decoding
    $ValidCertObj = @()
    foreach ($Validcred in $ValidCreds) {
        $ValidCertDetails = [System.Security.Cryptography.X509Certificates.X509Certificate2]([System.Convert]::FromBase64String($Validcred.Value))
        $CertObject = New-Object PSObject -Property ([ordered]@{
                Type       = $Validcred.Type
                Value      = $Validcred.Value
                KeyId      = $Validcred.KeyId
                Thumbprint = $ValidCertDetails.Thumbprint
                Subject    = $ValidCertDetails.Subject
                StartDate  = $ValidCertDetails.NotBefore
                EndDate    = $ValidCertDetails.NotAfter
                Usage      = $Validcred.Usage
            })
        $ValidCertObj += $CertObject
        Write-Log -String "Type: $($Validcred.Type)" -Name $Logname
        Write-Log -String "Value: $($Validcred.value)" -Name $Logname
        Write-Log -String "KeyId: $($Validcred.KeyId)" -Name $Logname
        Write-Log -String "Thumbprint: $($ValidCertDetails.Thumbprint)" -Name $Logname
        Write-Log -String "Subject: $($ValidCertDetails.Subject)" -Name $Logname
        Write-Log -String "StartDate: $($ValidCertDetails.NotBefore)" -Name $Logname
        Write-Log -String "EndDate: $($ValidCertDetails.NotAfter)" -Name $Logname
        Write-Log -String "Usage: $($Validcred.Usage)" -Name $Logname
        Write-Log -String "Clearing CertObject variable to ensure clean data for each Service Principal" -Name $Logname
        Clear-Variable CertObject
    }
    Write-Output $ValidCertObj
    # Array for storing expired certificates in memory to present to user after decoding
    $ExpiredCredObj = @()
    if ($ExpiredCreds.count -gt 0) {
        foreach ($ExpiredCred in $ExpiredCreds) {
            $ExpiredCredDetails = [System.Security.Cryptography.X509Certificates.X509Certificate2]([System.Convert]::FromBase64String($ExpiredCred.Value))            
            $ExpiredCertObject = New-Object PSObject -Property ([ordered]@{
                    Type       = $ExpiredCred.Type
                    Value      = $ExpiredCred.Value
                    KeyId      = $ExpiredCred.KeyId
                    Thumbprint = $ExpiredCredDetails.Thumbprint
                    Subject    = $ExpiredCredDetails.Subject
                    StartDate  = $ExpiredCredDetails.NotBefore
                    EndDate    = $ExpiredCredDetails.NotAfter
                    Usage      = $ExpiredCred.Usage
                })
            $ExpiredCredObj += $ExpiredCertObject
            Write-Log -String "Type: $($ExpiredCred.Type)" -Name $Logname
            Write-Log -String "Value: $($ExpiredCred.Value)" -Name $Logname
            Write-Log -String "KeyId: $($ExpiredCred.KeyId)" -Name $Logname
            Write-Log -String "Thumbprint: $($ExpiredCredDetails.Thumbprint)" -Name $Logname
            Write-Log -String "Subject: $($ExpiredCredDetails.Subject)" -Name $Logname
            Write-Log -String "StartDate: $($ExpiredCredDetails.NotBefore)" -Name $Logname
            Write-Log -String "EndDate $($ExpiredCredDetails.NotAfter)" -Name $Logname
            Write-Log -String "Usage $($ExpiredCred.Usage)" -Name $Logname
            Write-Log -String "Clearing ExpiredCertObject to ensure clean data for each Service Principal" -Name $Logname
            Clear-Variable ExpiredCertObject
        }
        Write-Host "Expired Certificates listed below" -ForegroundColor Red
        Write-Output $ExpiredCredObj
    }
    else {
        Write-Host "No expired certificates found" -ForegroundColor Green
    }

    Write-Host "Found $($ValidCreds.count) Valid certificates."
    Write-Log -String "Found $($ValidCreds.count) Valid certificates" -Name $Logname
    Write-Host "Found $($ExpiredCreds.count) Expired certificates"
    Write-Log -String "Found $($ExpiredCreds.count) Expired certificates" -Name $Logname
    Write-Log -String "Total number of Certificates found: $($Credentials.count)" -Name $Logname
    Write-host "Total number of Certificates found: $($Credentials.count)" -ForegroundColor Yellow
    Write-Host ""

    Read-Host -Prompt "Hit Enter key to continue"

    Get-UserInput
    
}

Write-Log -String "*********************************************************" -Name $Logname
Write-log -String "*                      START SCRIPT                     *" -Name $Logname
Write-log -String "*********************************************************" -Name $Logname
$ExecutingUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name
Write-Log -String "User Executing Script $($ExecutingUser)" -Name $Logname
function Start-Menu {
    # Init PowerShell Gui
    Write-Log -String "Loading menu of choices for user" -Name $Logname
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    # Create a new form
    [System.Windows.Forms.Application]::EnableVisualStyles()

    $AzureMFAForm = New-Object system.Windows.Forms.Form

    # Define the size, title and background color
    $AzureMFAForm.ClientSize = '400,250'
    $AzureMFAForm.text = "Azure MFA Certificate Utility"
    $AzureMFAForm.BackColor = "#ffffff"
    $AzureMFAForm.StartPosition = "CenterScreen"
    $AzureMFAForm.TopMost = $false

    $Font = New-Object System.Drawing.Font("Times New Roman", 11)
    $AzureMFAForm.Font = $Font

    $AzureMFGroup = New-Object System.Windows.Forms.GroupBox
    $AzureMFGroup.Location = '40,30'
    $AzureMFGroup.size = '300,150'
    $AzureMFGroup.Text = "Select an option on how to proceed"

    $Radiobtn1 = New-Object System.Windows.Forms.RadioButton
    $Radiobtn1.Location = '20,40'
    $Radiobtn1.Size = '350,20'
    $Radiobtn1.Checked = $false
    $Radiobtn1.Text = "Retrieve Current Azure MFA Certificates"

    $Radiobtn2 = New-Object System.Windows.Forms.RadioButton
    $Radiobtn2.Location = '20,70'
    $Radiobtn2.Size = '350,20'
    $Radiobtn2.Checked = $false
    $Radiobtn2.Text = "Delete Azure MFA Certificates"

    $OKButton = New-Object System.Windows.Forms.Button
    $OKButton.Location = '150,200'
    $OKButton.Size = '100,40'
    $OKButton.Text = 'OK'
    $OKButton.DialogResult = [System.Windows.Forms.DialogResult]::OK

    $CancelButton = New-Object System.Windows.Forms.Button
    $CancelButton.Location = '275,200'
    $CancelButton.Size = '100,40'
    $CancelButton.Text = 'Cancel'
    $CancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel

    $AzureMFGroup.Controls.AddRange(@($Radiobtn1, $Radiobtn2))

    $AzureMFAForm.Controls.AddRange(@($AzureMFGroup, $OKButton, $CancelButton))

    $AzureMFAForm.AcceptButton = $OKButton
    $AzureMFAForm.CancelButton = $CancelButton

    $AzureMFAForm.Add_Shown({ $AzureMFAForm.Activate() })

    $ButtonResult = $AzureMFAForm.ShowDialog()

    if ($ButtonResult -eq "OK") {
        if ($Radiobtn1.Checked -eq $true) { Get-CurrentCertificates }
        elseif ($Radiobtn2.Checked -eq $true) { Remove-Certificates }
    }
    else {
        if ($ButtonResult -eq "Cancel") { Write-Log "User selected Cancel ending application" -Name $Logname; Exit }
    }
    [void]$AzureMFAForm.ShowDialog()
}
Clear-Host
# Load Menu for choices
Start-Menu

