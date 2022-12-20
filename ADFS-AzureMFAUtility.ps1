# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.NOTES
	Name: ADFS-AzureNFAUtility.ps1
	Requires: PowerShell 5.1 as well as Administrative Privileges
    Major Release History:
        12/19/2022 - Initial Release

.SYNOPSIS
Automates the process for creating a new ADFS Azure MFA on an ADFS server. It also allows for renewing Azure MFA certificates, updating TLS keys
Checking and cleaning up Azure Multi-Factor Service Principals (Certs).
It also checks ADFS server prerequisites to help ensure a smooth deployment of ADFS Azure MFA enrollment. 

.DESCRIPTION
This utility will allow you to enable Azure MFA for an ADFS farm. All steps are automated from Microsoft ADFS Azure MFA documentation here:
https://docs.microsoft.com/en-us/windows-server/identity/ad-fs/operations/configure-ad-fs-and-azure-mfa
I've included a logging function to log everything that happens including retrieving the new certificate thumbprint and valid date.


.EXAMPLE
Can execute the script directly which will pull up a main menu for options on how you would like to proceed. It is recommended if this is a new setup
to run the Pre-Requisite check to confirm everything is currently setup and configured to allow for a quick Azure MFA setup.

#>
#Requires -Version 5.1
#Requires -RunAsAdministrator
$Global:ProgressPreference = 'SilentlyContinue'
#Log filename
$Logname = 'AzureMFAUtility.log'

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
}   # Function to check Azure connectivity or establish the connection if not present.
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
    # Get user feedback regarding deleting certificates
function Get-UserFeedback {
    begin {
        write-log -String "Prompting $($ExecutingUser) if they would like to delete additional certificates" -Name $Logname
        Add-Type -AssemblyName PresentationCore, PresentationFramework
        $Button = [System.Windows.MessageBoxButton]::YesNoCancel
        $Title = "Delete Certificates from Azure Multi-Factor Client Service?"
        $Icon = [System.Windows.MessageBoxImage]::Question
        $body = "Do you want to delete additonal certificates?"
    }

    process {
        $Result = [System.Windows.MessageBox]::Show($body, $Title, $Button, $Icon)

        if ($Result -eq 'Yes') {
            Write-Log -String "$($ExecutingUser) selected Yes to delete additional certificates" -Name $Logname
            Write-Log -String "Calling Get-AzureMFAClientCerts function" -Name $Logname
            Clear-Host
            Clear-Variable Cert, Certlist, CertDetails, CertObjectDetails
            Get-AzureMFAClientCerts
 
        }
        elseif ($Result -eq 'No') {
            Write-Log -String "$($ExecutingUser) selected No to remove additional certificates" -Name $Logname
            Write-Log -String "Ending script" -Name $Logname
            Clear-Host
            Write-Host ""
            Write-Host "Script completed, no additional certificates will be removed."
            Write-Host ""
            Read-Host -Prompt "Hit enter to exit"
            Exit
        }
        elseif ($Result -eq 'Cancel') {
            Write-Log -String "$($ExecutingUser) selected cancel, exiting script" -Name $Logname
            Write-Host "Script completed, no changes have been made."
            Exit
        }
    }
    End {
        Write-Log -String "Ending Get-UserInput function" -Name $Logname
    }
    
}
    # Function to provide details to the user regarding the newly generated certificate.
function Get-NewCert {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true)]
        [string[]]
        $Cert = $CertName,

        [string[]]
        $Server = $Name
        
    )
    Begin {
        Write-Log -String "Get-NewCert function called with tenant ID of $Cert " -Name $Logname
        $NewCertCheck = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object { $_.Subject -like "CN=$Cert*" }
        $NewCertObject = [PSCustomObject]@{
            Server     = $Server
            Subject    = $NewCertCheck.Subject
            Thumbprint = $NewCertCheck.Thumbprint
            Issued     = $NewCertCheck.NotBefore
            Expires    = $NewCertCheck.NotAfter
        }
    }
    process {

        foreach ($object in $NewCertObject) {
            foreach ($i in $object.PSObject.Properties) {
                Write-Log -String "$($i.Name), $($i.Value)" -Name $Logname
                Write-Host ""
                Write-Host "$($i.Name), $($i.Value)"
            }
        }
        Write-Host ""
        Write-Host "New certificate has been uploaded to Azure MFA"
        Read-Host -Prompt "Hit enter to continue"
    }
    End {
        Write-Log -String "Ending Get-NewCert function" -Name $Logname
    }

}
    # Function to automate the enabling of Azure MFA for ADFS environment (Should only prompt on Primary ADFS). Note: May prompt for ADFS servers with SQL backend
    # if already ran once in the environment, can select NO.
function Enable-AzureMFA {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true)]
        [string[]]
        $Cert = $CertName
    )

    Write-Log -String "Enable AzureMFA function called, using $Cert as TenantId" -Name $Logname
    Clear-Host
    Add-Type -AssemblyName PresentationCore, PresentationFramework
    $AzureMFAButton = [System.Windows.MessageBoxButton]::YesNoCancel
    $AzureMFAPopupTitle = "Enable Azure MFA for ADFS Farm?"
    $AzureMFAPopupIcon = [System.Windows.MessageBoxImage]::Question
    $AzureMFAPopupbody = "Do you want to enable Azure MFA functionality for your ADFS Farm? (This only needs to be run once for New Deployments Only!)"
    $AzureMFAPopupResult = [System.Windows.MessageBox]::Show($AzureMFAPopupbody, $AzureMFAPopupTitle, $AzureMFAButton, $AzureMFAPopupIcon)
    if ($AzureMFAPopupResult -eq "Yes") {
        Write-Log -String "$($ExecutingUser) selected Yes to enable Azure MFA for ADFS Farm" -Name $Logname
        Write-Log -String "Enabling AzureMFA using command: Set-AdfsAzureMfaTenant -TenantId $Cert -ClientId 981f26a1-7f43-403b-a875-f8b09b8cd720" -Name $Logname
        try {
            Set-AdfsAzureMfaTenant -TenantId "$($Cert)" -ClientId 981f26a1-7f43-403b-a875-f8b09b8cd720
            Write-Log -String "Set-AdfsAzureMfaTenant completed successfully" -Name $Logname
            Clear-Host
            Write-Host ""
            Write-Host "ADFS Azure MFA enabled for farm" -ForegroundColor Green
            Write-Host ""
            Write-Log -String "Prompting $($ExecutingUser) to restart Federation service" -Name $Logname
            Read-Host -Prompt "Hit enter key to continue"
            Restart-ServiceNotification
        }
        catch {
            Write-Log -String "Failed to enable ADFS Azure MFA" -Name $Logname
            Write-Log -String "Exception encountered $($_.Exception.Message)" -Name $Logname
        }
    }
    elseif ($AzureMFAPopupResult -eq "No") {
        Write-Log -String "$($ExecutingUser) selected No to enable Azure MFA returning to main menu" -Name $Logname
        Start-Menu
    }
    elseif ($AzureMFAPopupResult -eq "Cancel") {
        Write-Log -String "$($ExecutingUser) selected Cancel, exiting scipt" -Name $Logname
        Exit
    }    
}
    # Restart ADFS service, called after making TLS changes which neccitates restarting the server for the changes to take affect.
function Restart-ServiceNotification {
  
    begin {
        write-log -String "Prompting $($ExecutingUser) to restart ADFS service" -Name $Logname
        Add-Type -AssemblyName PresentationCore, PresentationFramework
        $RestartButton = [System.Windows.MessageBoxButton]::YesNoCancel
        $RestartPopupTitle = "Restart Active Directory Federation Service"
        $RestartPopupIcon = [System.Windows.MessageBoxImage]::Question
        $RestartPopupbody = "Did you want to restart the Active Directory Federation service?"
    }

    process {
        $RestartPopupResult = [System.Windows.MessageBox]::Show($RestartPopupbody, $RestartPopupTitle, $RestartButton, $RestartPopupIcon)

        if ($RestartPopupResult -eq 'Yes') {
            Write-Log -String "$($ExecutingUser) selected Yes to restart ADFS service" -Name $Logname
            try {
                Restart-Service -Name adfssrv -PassThru
            }
            catch {
                Write-Log -String "Encountered exception $($_.Exception.Message)"
                Write-Host "Encountered an exception with restarting the ADFS service, you will have to restart manually" -ForegroundColor Red
                Write-Error "$($_.Exception.Message)" -ErrorAction Stop
            }
            Read-Host -Prompt "Press Enter to Continue"
            Clear-Host
            Start-Menu
        }
        elseif ($RestartPopupResult -eq 'No') {
            Write-Log -String "$($ExecutingUser) selected No to restart ADFS service" -Name $Logname
            Write-Host "You will need to restart the service at a later date for the changes to take effect"
            Read-Host -Prompt "Press Enter key to continue"
            Start-Menu
        }
        elseif ($RestartPopupresult -eq 'Cancel') {
            Write-Log -String "$($ExecutingUser) selected cancel to restart ADFS service" -Name $Logname
            Start-Menu
        }
    }
    End {
        Write-Log -String "Ending Restart-ServiceNotification function" -Name $Logname
    }
}
    # Function to check system pre-requisites to confirm that the system is in line with Microsoft Documentation:
    # https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/operations/configure-ad-fs-and-azure-mfa#pre-requisites
function Get-OnPremPreRequisites {
    Write-Log -String "$($ExecutingUser) selected Check ADFS Azure MFA Pre-Requisites" -Name $Logname
    Write-Log -String "Checking if machine is domain joined" -Name $Logname
    try {
        $Domainjoined = [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain()
    }
    catch {
        Write-Log -String "Exception encountered $($_.Exception.Message)" -Name $Logname
    }
    if ($null -ne $Domainjoined) { $Joined = $true } else { $Joined = $false }
    Write-Log -String "Server is Domain joined $Joined" -Name $Logname
    $DomainName = $Domainjoined.Name
    $Hostname = ([System.Net.Dns]::GetHostByName(($env:COMPUTERNAME))).Hostname
    Write-Log -string "Pulling OS details" -Name $Logname
    $OS = Get-WmiObject win32_operatingsystem | Select-Object Caption, OSArchitecture, Version, BuildNumber
    # Thanks to Christian Weisse for the below method for locating Enterprise Admins membership.
    Write-Log -String "Pulling security principal" -Name $Logname
    $Groups = [System.Security.Principal.WindowsIdentity]::GetCurrent().Groups 
    $Sid = foreach ($Sid in $Groups) {
        if ($sid.Translate([Security.Principal.SecurityIdentifier]).IsWellKnown([Security.Principal.WellKnownSidType]::AccountEnterpriseAdminsSid)) {
            $Sid
            Write-Log -String "Enterprise Admin Sid: $Sid" -Name $Logname
        }
    }
    Write-Log -String "Setting EnterpriseAdmin to True or False" -Name $Logname
    if ($null -ne $Sid) { $EnterpriseAdmin = $true } else { $EnterpriseAdmin = $false }
    Write-Log -String "EnterpriseAdmin is $EnterpriseAdmin" -Name $Logname
    $OpenReg = [Microsoft.Win32.Registry]::LocalMachine
    $RegKeyPath = 'SOFTWARE\Microsoft\.NETFramework\v4.0.30319'
    $RegKey = $OpenReg.OpenSubKey($RegKeyPath)
    $UseStrongCrypto = $RegKey.GetValue('SchUseStrongCrypto')
    $SystemDefault = $RegKey.GetValue('SystemDefaultTlsVersions')
    $UseStrongCryptoExists = if ($UseStrongCrypto) { $true }else { $false }
    $SystemDefaultExists = if ($SystemDefault) { $true }else { $false }
    Write-Log -String "Variable paths to check for TLS keys $RegKeyPath, $UseStrongCryptoExists, $SystemDefaultExists" -Name $Logname
    Write-Log -String "TLS 1.2 SchUseStrongCrypto Registry Key Exists, $UseStrongCryptoExists, Registry Key Value, $UseStrongCrypto" -Name $Logname
    Write-Log -String "TLS 1.2 SystemDefaultTLSVersions Registry Key Exists, $SystemDefaultExists, Registry Key Value $SystemDefault" -Name $Logname
  
    if ($UseStrongCryptoExists -eq "True" -and $UseStrongCrypto -eq 1 -and $SystemDefaultExists -eq "True" -and $SystemDefault -eq 1 ) { $TLS12Compliance = "TLS 1.2 Compliant" } else { $TLS12Compliance = "TLS 1.2 Non-compliant" }

    $ADFSRole = (Get-WindowsFeature -Name ADFS-Federation).installed
    $MSonlineModule = Get-Module -ListAvailable -Name MSOnline | Select-Object Name, Version, Path
    if ($null -eq $MSonlineModule) { $MSonlineModuleExists = $false } else { $MSonlineModuleExists = $true }
    if ($MSonlineModuleExists -eq $false) { $MSModule = 'Not Installed' } else { $MSModule = 'Installed' }
    if ($MSonlineModuleExists -eq $false) { $MSModuleVersion = 'Not Installed' } else { $MSModuleVersion = $MSonlineModule.Version }

    $DNSEndpoint1 = 'adnotifications.windowsazure.com'
    $DNSEndpoint2 = 'login.microsoftonline.com'
        
    $Endpoint1 = try {
        Resolve-DnsName -Name $DNSEndpoint1 | Select-Object IPAddress | Where-Object { $null -ne $_.IPAddress }
        Write-Log -String "Endpoint1 $DNSEndpoint1 resolved successfully"  -Name $Logname   
    }
    catch {
        Write-Log -String "Unable to resolve DNS for $DNSEndpoint1" -Name $Logname
    }
    $Endpoint1IPHashTable = @{}
    $Port = 443
    $Timeout = 1000
    foreach ($IP in $Endpoint1) {
        Write-Log -String "IP Address returned for $DNSEndpoint1, $($IP.IPAddress)" -Name $Logname
        $TCPClient = New-Object System.Net.Sockets.TcpClient
        if ($TCPClient.ConnectAsync($($IP.IPAddress), $($Port)).Wait($Timeout)) {
            $TCPClient.Dispose()
            $CheckIP = "True"
            Write-Log -String "Adding $($IP.IPAddress) and status $($CheckIP) to HashTable" -Name $Logname
            $Endpoint1IPHashTable.Add($IP.IPAddress, $CheckIP)
            Write-Log -String "IP $($IP.IPAddress) connected over port 443 [ $($CheckIP) ]" -Name $Logname
        }
        else {
            $TCPClient.Dispose()
            $CheckIP = "False"
            $Endpoint1IPHashTable.Add($IP.IPAddress, $CheckIP)
            Write-Log -String "IP $($IP.IPAddress) connected over port 443 [ $($CheckIP) ]" -Name $Logname
        }
    }        
    $Endpoint2 = try {
        Resolve-DnsName -Name $DNSEndpoint2 | Select-Object IPAddress | Where-Object { $null -ne $_.IPAddress }
        Write-Log -String "Endpoint2 $DNSEndpoint2 resolved successfully" -Name $Logname
        
    }
    catch {
        Write-Log -String "Unable to resolve DNS For $DNSEndpoint2" -Name $Logname
    }
    Clear-Variable CheckIP, TcpClient
    $Endpoint2IPHashTable = @{}
    foreach ($IP in $Endpoint2) {
        Write-Log -String "IP Address returned for $DNSEndpoint2, $($IP.IPAddress)" -Name $Logname
        $TCPClient = New-Object System.Net.Sockets.TcpClient
        if ($TCPClient.ConnectAsync($($IP.IPAddress), $($Port)).Wait($Timeout)) {
            $TCPClient.Dispose()
            $CheckIP = "True"
            Write-Log -String "Adding $($IP.IPAddress) and status $($CheckIP) to HashTable" -Name $Logname
            $Endpoint2IPHashTable.Add($IP.IPAddress, $CheckIP)
            Write-Log -String "IP $($IP.IPAddress) connected over port 443 [ $($CheckIP) ]" -Name $Logname
        }
        else {
            $TCPClient.Dispose()
            $CheckIP = "False"
            $Endpoint2IPHashTable.Add($IP.IPAddress, $CheckIP)
            Write-Log -String "IP $($IP.IPAddress) connected over port 443 [ $($CheckIP) ]" -Name $Logname
        }        
    }
    Clear-Host
    if ($null -ne $Endpoint1.IPAddress) {
        $DNSResolved1 = $true
        try {
            $TestConnectivity1 = Test-NetConnection -ComputerName $DNSEndpoint1 -Port 443
            Write-Log -String "Test connectivity to $DNSEndpoint1 over port 443 completed successfully" -Name $Logname
        }
        catch {
            $DNSResolved1 = $false
            Write-Log -String "Failed to connect to $DNSEndpoint1 over port 443" -Name $Logname
        }        
    }
    if ($null -ne $Endpoint2.IPAddress) {
        $DNSResolved2 = $true
        try {
            $TestConnectivity2 = Test-NetConnection -ComputerName $DNSEndpoint2 -Port 443
            Write-Log -String "Test connectivity to $DNSEndpoint2 over port 443 completed successfully" -Name $Logname
        }
        catch {
            $DNSResolved2 = $false
            Write-Log -String "Failed to connect to $DNSEndpoint2 over port 443" -Name $Logname
        }
        
    }
    # PS Custom Object for returning what was found in a readable format for the user.
    $ServerInfo = [PSCustomObject]@{
        ServerName        = $Hostname
        DomainJoined      = $Joined
        DomainName        = $DomainName
        EnterpriseAdmin   = $EnterpriseAdmin
        OperatingSystem   = $OS.Caption
        OSBitness         = $OS.OSArchitecture
        OSVersion         = $OS.Version
        OSBuildNumber     = $OS.BuildNumber
        ADFSRole          = $ADFSRole
        MSOnlineInstalled = $MSonlineModuleExists
        MSOnlineVersion   = $MSModuleVersion
        TLS12Compliance   = $TLS12Compliance
    }
    Write-Host "*************************************************************************"
    Write-Host "*                  ADFS Server PreRequisite Results                     *"
    Write-Host "*************************************************************************"
    Write-Host ""
    Write-Output $ServerInfo
    Write-Log -String "ServerInfo Output Results.." -Name $Logname
    foreach ($object in $ServerInfo) {
        foreach ($i in $object.PSObject.Properties) {
            Write-log -String "$($i.Name), $($i.Value)" -Name $Logname
        }
    }
    # Endpoint 1 details regarding DNS resolution and connectivity
    $Endpoint1Details = [PSCustomObject]@{
        Endpoint          = $DNSEndpoint1
        DNSResolved       = $DNSResolved1
        EndpointIP        = $TestConnectivity1.RemoteAddress
        Port443Accessible = $TestConnectivity1.TcpTestSucceeded
    }
    Write-Output $Endpoint1Details
    Write-Log -String "Endpoint1 Output Results.." -Name $Logname
    foreach ($object in $Endpoint1Details) {
        foreach ($i in $object.PSObject.Properties) {
            Write-log -String "$($i.Name), $($i.Value)" -Name $Logname
        }
    }
    # Endpoint 2 details regarding DNS resolution and connectivity
    $Endpoint2Details = [PSCustomObject]@{
        Endpoint          = $DNSEndpoint2
        DNSResolved       = $DNSResolved2
        EndpointIP        = $TestConnectivity2.RemoteAddress
        Port443Accessible = $TestConnectivity2.TcpTestSucceeded         
    }
    Write-Output $Endpoint2Details
    Write-Log -String "Endpoint2 Output Results.." -Name $Logname
    foreach ($object in $Endpoint2Details) {
        foreach ($i in $object.PSObject.Properties) {
            Write-log -String "$($i.Name), $($i.Value)" -Name $Logname
        }
    }
    # List details of items returned and let user know of items that may need to be addressed before moving forward.
    if ($OS.Version -ge '10.0.14393') { Write-Host "Server OS meets minimum requirements" -ForegroundColor Green } else {
        Write-Host "Server OS DOES NOT meet minimum requirements" -ForegroundColor Red
    }
    if ($EnterpriseAdmin -eq "True") { Write-Host "Current user $($ExecutingUser) is Enterprise Admin" -ForegroundColor Green } else {
        Write-Host "Current user $($ExecutingUser) is not an Enterprise Admin" -ForegroundColor Red
    }
    if ($Joined -eq $true) { Write-Host "Server is Domain Joined" -ForegroundColor Green } else { 
        Write-Host "Server is not joined to a domain" -ForegroundColor Red
    }
    if ($MSModule -eq 'Installed') { Write-Host "MS Online Module Installed" -ForegroundColor Green } else {
        Write-Host "MS Online Module NOT installed" -ForegroundColor Red
    }
    if ($ADFSRole -eq $true) { Write-Host "ADFS Role Installed" -ForegroundColor Green }
    else {
        Write-Host "ADFS Role NOT installed" -ForegroundColor Red 
    }
    if ($UseStrongCryptoExists -eq "True" -and $SystemDefaultExists -eq "True") { Write-Host "System is TLS 1.2 compliant" -ForegroundColor Green } else {
        Write-Host "System is NOT TLS 1.2 Compliant" -ForegroundColor Red
    }
    $Endpoint1Object = New-Object PSObject
    foreach ($Obj in $Endpoint1IPHashTable.GetEnumerator()) {
        if ($Obj.Value -Like "False") {
            Write-Log -String "Endpoint with IP $($Obj.Name) for $DNSEndpoint1 DID NOT resolve successfully" -Name $Logname
            Write-Log -String "Unable to connect to IP $($Obj.Name)" -Name $Logname
            $Endpoint1Object | Add-Member -MemberType NoteProperty -Name $Obj.Name -Value $Obj.Value
        }
        else {
       
            Write-Log -String "Endpoint with IP $($Obj.Name) for $DNSEndpoint1 resolved and connected successfully over port 443" -Name $Logname
        }
    }
    $Endpoint1Array = $Endpoint1Object | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name
    if ($null -ne $Endpoint1Array) {
        Write-Host "Following IP(S) for $DNSEndpoint1 were unable to connect over port 443" -ForegroundColor Red
        Write-Host ""
        Write-Output $Endpoint1Array
        Write-Host ""
        Write-Host "Check Azure MFA Utility Log for further details"            
    }
    else {
        Write-Host "All IP Addresses for $DNSEndpoint1 resolved successfully" -ForegroundColor Green    
    }
    $Endpoint2Object = New-Object psobject 
    foreach ($Entry in $Endpoint2IPHashTable.GetEnumerator()) {
        if ($Entry.Value -like "False") {
            Write-Log -String "Endpoint with IP $($Entry.Name) for $DNSEndpoint2 DID NOT resolve or connect successfully over port 443" -Name $Logname
            Write-Log -String "Unable to connect to IP $($Entry.Name)" -Name $Logname
            $Endpoint2Object | Add-Member -MemberType NoteProperty -Name $Entry.Name -Value $Entry.Value
        }
        else {
            Write-Log -String "Endpoint with IP $($Entry.Name) for $DNSEndpoint2 resolved and connected successfully over port 443" -Name $Logname
        } 
    }
    $Endpoint2Array = $Endpoint2Object | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name
    if ($null -ne $Endpoint2Array) {
        Write-Host "Following IP(s) for $DNSEndpoint2 were unable to connect over port 443" -ForegroundColor Red
        Write-Host ""
        Write-Output $Endpoint2Array
        Write-Host ""
        Write-Host "Check Azure MFA Utility Log for further details"      
    }
    else {
        Write-Host "All IP Addreses for $DNSEndpoint2 resolved successfully"  -ForegroundColor Green     
    }
    if ($TestConnectivity1.TcpTestSucceeded -eq $true -and $null -eq $Endpoint1Array) { Write-Host "Port 443 is reachable for all IP Addresses associated with '$DNSEndpoint1'" -ForegroundColor Green }
    else {
        Write-Host "Port 443 is UNREACHABLE for some or all IP addresses associated with '$DNSEndpoint1' " -ForegroundColor Red
    }
    if ($TestConnectivity2.TcpTestSucceeded -eq $true -and $null -eq $Endpoint2Array) { Write-Host "Port 443 is reachable for all IP addresses associated with '$DNSEndpoint2'" -ForegroundColor Green } else {
        Write-Host "Port 443 is UNREACHABLE for some or all IP addresses associated with '$DNSEndpoint2'" -ForegroundColor Red
    }
    if ($OS.Version -ge '10.0.14393' -and $EnterpriseAdmin -eq 'True' -and $Joined -eq 'True' -and $ADFSRole -eq $true -and $UseStrongCryptoExists -eq 'True' -and $SystemDefaultExists -eq 'True' -and $MSModule -eq 'Installed' -and $DNSResolved1 -eq $true -and $DNSResolved2 -eq $true -and $null -eq $Endpoint1Array -and $null -eq $Endpoint2Array) {
        Write-host " "
        Write-Host "On Premises Server meets requirements to proceed with setting up Azure AD MFA" -ForegroundColor Green; Write-Log -String "On Premises Server meets requirements to proceed with setting up Azure AD MFA" -Name $Logname
        Read-Host -Prompt "Hit Enter key to continue"
        Start-Menu
    }
    else {
        Write-Host " "
        Write-Host "Missing full requirements to proceed, please check the list above and correct any errors..." -ForegroundColor Red; Write-Log -String "Missing full requirements to proceed, please check the list above and correct any errors..." -Name $Logname
        Read-Host -Prompt "Hit Enter key to continue"
        Start-Menu
    }
}
    # New MFA Certificate to generate and upload an Azure MFA certificate. Does a check to make sure an existing certificate does not exist.
function New-MfaCertificate {
    Clear-Host
    Write-Host " "
    $Name = $env:COMPUTERNAME
    Write-Log -String "$($ExecutingUser) selected New ADFS Azure MFA Setup" -Name $Logname
    $CertName = Read-Host -Prompt "Tenant id Please (example contoso.onmicrosoft.com)"
    Clear-Host
    Write-Log -String "$($ExecutingUser) entered tenant id: $CertName" -Name $Logname
    $Certcheck = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object { $_.DnsNameList -contains "$CertName" }
    Add-Type -AssemblyName PresentationCore, PresentationFramework
    $Button = [System.Windows.MessageBoxButton]::YesNoCancel
    $PopupTitle = "Tenant id Verification"
    $PopupIcon = [System.Windows.MessageBoxImage]::Question
    $Popupbody = "Is your Tenant id correct? $CertName"

    $PopupResult = [System.Windows.MessageBox]::Show($Popupbody, $PopupTitle, $Button, $PopupIcon)
    if ($PopupResult -eq "Yes") {
        if ($null -ne $Certcheck.Thumbprint) {
            $ExistingCert = [PSCustomObject]@{
                Subject    = $Certcheck.Subject
                Thumbprint = $Certcheck.Thumbprint
                Issued     = $Certcheck.NotBefore
                Expires    = $Certcheck.NotAfter
                
            }
            
            Write-Log -String "Certificate with that name already exists" -Name $Logname
            foreach ($object in $ExistingCert) {
                foreach ($i in $object.PSObject.Properties) {
                    Write-log -String "$($i.Name), $($i.Value)" -Name $Logname
                    Write-Host ""
                    Write-Host "$($i.Name), $($i.Value)"                  
                }
                
            }
            Write-Host "Certificate with that name already exists" -ForegroundColor Red
            Write-Log -String "Not able to proceed, stopping script." -Name $Logname
            Write-Error "Verify if this is a new configuration, and if so delete existing certificate"
            Read-Host -Prompt "Press Enter to Exit"
            Exit
        }
        
        else {
            try {   # IF statement for Windows Server 2019+ per documents requires an ADFS Claims Provider Trust. Document for requirement linked below.
                if ($OS.Version -ge '10.0.17763') {
                    Write-Log -String "Server 2019 detected, have to set AdfsClaimsProviderTrust per requirements" -Name $Logname
                    <# With AD FS 2019, you are required to make a modification to the anchor claim type for the Active Directory Claims Provider trust 
                    and modify this from the windowsaccountname to UPN. Execute the PowerShell cmdlet provided below. 
                    This has no impact on the internal functioning of the AD FS farm. You may notice a few users may be re-prompted for credentials once this change is made. 
                    After logging in again, end users will see no difference.
                    https://docs.microsoft.com/en-us/windows-server/identity/ad-fs/operations/configure-ad-fs-and-azure-mfa
                    #>
                    Set-AdfsClaimsProviderTrust -AnchorClaimType "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn" -TargetName "Active Directory"
                    Write-Log -String "Claims provider trust updated per ADFS 2019 requirements" -Name $Logname
                    Write-Log -String "Certificate with name $CertName did not exist, proceeding to generate certificate on Server $Name" -Name $Logname
                    $NewCert = New-AdfsAzureMfaTenantCertificate -TenantId $CertName
                    Write-Log -String "$($ExecutingUser) created new certificate $NewCert" -Name $Logname
                    Write-Log -String "Attempting to upload Certificate for Azure Multi-Factor Auth Client" -Name $Logname
                    #Upload to Azure Application for MFA
                    Get-MSOLServiceConnection
                    Try {
                        New-MsolServicePrincipalCredential -AppPrincipalId 981f26a1-7f43-403b-a875-f8b09b8cd720 -Type asymmetric -Usage verify -Value $NewCert
                    }
                    Catch {
                        Write-Log -String "Failed to upload certificate" -Name $Logname
                        Write-Log -String "Exception encountered $($_.Exception.Message)" -Name $Logname
                    }
                    Get-NewCert
                    Write-Log -String "Checking if server is primary in ADFS farm to enable ADFS Azure MFA." -Name $Logname
                    $Primary = Get-AdfsSyncProperties
                    if ($Primary.Role -eq "PrimaryComputer") {
                        Write-Log -String "Server is primary in ADFS Farm, calling Enable-AzureMFA function" -Name $Logname
                        Enable-AzureMFA
                    }
                    else {
                        Write-Log -String "Server is not Primary in ADFS Farm, returning to main menu" -Name $Logname
                        Start-Menu
                    }
                }
                else {  # If statement for generating a certificate and enabling Azure MFA for Windows Server 2016.
                    Write-Log -String "Certificate with name $CertName did not exist, proceeding to generate certificate on Server $Name" -Name $Logname
                    $NewCert = New-AdfsAzureMfaTenantCertificate -TenantId $CertName
                    Write-Log -String "$($ExecutingUser) created new certificate $NewCert" -Name $Logname
                    Write-Log -String "Attempting to upload Certificate for Azure Multi-Factor Auth Client" -Name $Logname
                    #Upload to Azure Application for MFA
                    Get-MSOLServiceConnection
                    try {
                        New-MsolServicePrincipalCredential -AppPrincipalId 981f26a1-7f43-403b-a875-f8b09b8cd720 -Type asymmetric -Usage verify -Value $NewCert
                    }
                    catch {
                        Write-Log -String "Failed to upload certificate" -Name $Logname
                        Write-Log -String "Exception encountered $($_.Exception.Message)" -Name $Logname
                    }
                    Get-NewCert
                    Write-Log -String "Checking if server is primary in ADFS farm to enable ADFS Azure MFA." -Name $Logname
                    $Primary = Get-AdfsSyncProperties
                    if ($Primary.Role -eq "PrimaryComputer") {
                        Write-Log -String "Server is primary in ADFS Farm, calling Enable-AzureMFA function" -Name $Logname
                        Enable-AzureMFA
                    }
                    else {
                        Write-Log -String "Server is not Primary in ADFS Farm, returning to main menu" -Name $Logname
                        Start-Menu
                    }
                   
                }
            }
            catch {
                Write-Log -String "Error during generation of new Azure MFA certificate" -Name $Logname
                Write-Log -String "Exception encountered $($_.Exception.Message)" -Name $Logname
                Write-Error "Unable to generate new certificate review log for exception details" -ErrorAction Stop
            } 
      
        }
    
    }
       
    elseif ($PopupResult -eq "No") {
        Write-Log -string "$($ExecutingUser) selected no for name is not correct, returning to function to ask again" -Name $Logname
        New-MfaCertificate
    } 
    elseif ($PopupResult -eq "Cancel") {
        Write-Log -String "$($ExecutingUser) selected cancel to exit the script" -Name $Logname
        Clear-Host; Exit
    }
    
}  

function Update-Tls {
    #Status codes used for testing remote connectivity.
    $StatusCodes = @{
        [uint32]0     = 'Success';
        [uint32]11001 = 'Buffer Too Small';
        [uint32]11002 = 'Destination Net Unreachable';
        [uint32]11003 = 'Destination Host Unreachable';
        [uint32]11004 = 'Destination Protocol Unreachable';
        [uint32]11005 = 'Destination Port Unreachable';
        [uint32]11006 = 'No Resources';
        [uint32]11007 = 'Bad Option';
        [uint32]11008 = 'Hardware Error';
        [uint32]11009 = 'Packet Too Big';
        [uint32]11010 = 'Request Timed Out';
        [uint32]11011 = 'Bad Request';
        [uint32]11012 = 'Bad Route';
        [uint32]11013 = 'TimeToLive Expired Transit';
        [uint32]11014 = 'TimeToLive Expired Reassembly';
        [uint32]11015 = 'Parameter Problem';
        [uint32]11016 = 'Source Quench';
        [uint32]11017 = 'Option Too Big';
        [uint32]11018 = 'Bad Destination';
        [uint32]11032 = 'Negotiating IPSEC';
        [uint32]11050 = 'General Failure'
    }

    Write-Log -String "$($ExecutingUser) selected to fix TLS 1.2 compliance" -Name $Logname
    try {
        $Writable = $true
        # Update TLS 1.2 Client / Sever registry keys (Not required for 2016+ but is a good indicator for TLS 1.2 modification.)
        Write-Log -String "Updating TLS 1.2 client and Server keys" -Name $Logname
        $Key = (Get-Item HKLM:\).OpenSubKey("SYSTEM", $Writable).CreateSubKey("CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client")
        $Key.SetValue("Enabled", "1", [Microsoft.Win32.RegistryValueKind]::DWORD)
        $Key.SetValue("DisabledByDefault", "0", [Microsoft.Win32.RegistryValueKind]::DWORD)
        $Key = (Get-Item HKLM:\).OpenSubKey("SYSTEM", $Writable).CreateSubKey("CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server")
        $Key.SetValue("Enabled", "1", [Microsoft.Win32.RegistryValueKind]::DWORD)
        $Key.SetValue("DisabledByDefault", "0", [Microsoft.Win32.RegistryValueKind]::DWORD)
        # Have to tell .NET 4.0/4.5 to use TLS 1.2 (I.E. SchUseStrongCrypto) and set System Default TLS to 1.2
        Write-Log -String "Updating .NET 4.0/4.5 SchUseStrongCrypto and SystemDefaultTlsVersion keys" -Name $Logname
        $Key = (Get-Item HKLM:\).OpenSubKey("SOFTWARE", $Writable).CreateSubKey("Microsoft\.NETFramework\v4.0.30319")
        $Key.SetValue("SchUseStrongCrypto", "1", [Microsoft.Win32.RegistryValueKind]::DWORD)
        $Key.SetValue("SystemDefaultTlsVersions", "1", [Microsoft.Win32.RegistryValueKind]::DWORD)
        # Enable TLS 1.2 for 32-bit applications installed on a 64-bit OS.
        Write-Log "Updating .NET keys for 32-bit applications installed on 64-bit OS." -Name $Logname
        $Key = (Get-Item HKLM:\).OpenSubKey("SOFTWARE", $Writable).CreateSubKey("Wow6432Node\Microsoft\.NETFramework\v2.0.50727")
        $Key.SetValue("SchUseStrongCrypto", "1", [Microsoft.Win32.RegistryValueKind]::DWORD)
        $Key.SetValue("SystemDefaultTlsVersions", "1", [Microsoft.Win32.RegistryValueKind]::DWORD)
        $Key = (Get-Item HKLM:\).OpenSubKey("SOFTWARE", $Writable).CreateSubKey("WOW6432Node\Microsoft\.NETFramework\v4.0.30319")
        $Key.SetValue("SchUseStrongCrypto", "1", [Microsoft.Win32.RegistryValueKind]::DWORD)
        $Key.SetValue("SystemDefaultTlsVersions", "1", [Microsoft.Win32.RegistryValueKind]::DWORD)
        Clear-Host
        Write-Host ""
        Write-Host "You will need to reboot this server manually for the changes to take effect."
        Read-Host -Prompt "Press Enter to continue"
        Clear-Host
    }
    catch {
        Write-Log -String "Exception encountered $($_.Exception.Message)" -Name $Logname
        Write-Error "Exception encountered during TLS registry key update procedure please review log for error details" -ErrorAction Stop
    }
    # Prompt user if they would like to update TLS on another ADFS server remotely.
    Add-Type -AssemblyName PresentationCore, PresentationFramework
    $Button = [System.Windows.MessageBoxButton]::YesNoCancel
    $PopupTitle = "Fix TLS 1.2 on other ADFS Servers?"
    $PopupIcon = [System.Windows.MessageBoxImage]::Question
    $Popupbody = "Would you like to update the TLS 1.2 registry settings on additional servers?"

    $PopupResult = [System.Windows.MessageBox]::Show($Popupbody, $PopupTitle, $Button, $PopupIcon)

    if ($PopupResult -eq "Yes") {
        Write-log -String "$($ExecutingUser) selected Yes to update TLS 1.2 settings on other ADFS servers" -Name $Logname
        Clear-Host
        Write-Host ""
        Write-Host "Please enter the name(s) of servers you would like to update TLS 1.2 registry settings for."
        Write-Host "Names are entered as FQDN without spaces separated by commas (Example: adfs01.contoso.com,adfs02.contoso.com,etc.)"
        $PromptUser = Read-Host -Prompt "Name(s) of server(s)"; Clear-Host
        [array]$ServerNames = $PromptUser.Split(",")
        Write-Log -String "Server names $ServerNames to update TLS 1.2 settings" -Name $Logname
        if ($null -ne $ServerNames) {
            foreach ($Server in $ServerNames) {
                Write-Log "Checking server $Server" -Name $Logname
                Try {
                    $ServerDNS = Resolve-DnsName -Name $Server -Type A
                }
                catch {
                    Write-Log -String "DNS resolution failed $($_.Exception.Message)" -Name $Logname
                    Write-Error "Failed to resolve IP for $Server" 
                }
                $ServerIP = $ServerDNS.IPAddress
                Write-Log -String "Server $Server resolves to IP $ServerIP" -Name $Logname
                if ( $null -ne $ServerIP ) {
                    try {
                        $ServerCheck = Get-CimInstance -ClassName Win32_PingStatus -Filter "Address='$ServerIP' AND Timeout=1000"
                        Write-Log -String "Status Code returned from checking server connectivity via ping:[ $($StatusCodes[$ServerCheck.StatusCode]) ]" -Name $Logname
                    }
                    catch {
                        Write-Log -String "Failed to connect to server $Server" -Name $Logname
                        Write-Log -String "Exception encountered $($_.Exception.Message)" -Name $Logname
                        Write-Error $_.Exception.Message -ErrorAction SilentlyContinue
                    }
                }
                else {
                    Write-Log -String "Unable to resolve IP for server $Server" -Name $Logname
                    Write-Host "Unable to resolve IP for server $Server"
                }
                if ($ServerCheck.StatusCode -eq 0 ) {
                    Write-Log -String "Creating remote session for server $Server" -Name $Logname
                    Try {
                        # Update TLS 1.2 Client / Sever registry keys (Not required for 2016+ but is a good indicator for TLS 1.2 modification.)
                        Write-Log -String "Updating TLS Client and Server Keys for server $Server" -Name $Logname
                        $BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $Server)
                        $SubKey = $BaseKey.OpenSubKey("SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\", $true)
                        $SubKey.CreateSubKey("TLS 1.2\Client") | Out-Null
                        $SubKey.CreateSubKey("TLS 1.2\Server") | Out-Null
                        $TLSClientSubKey = $BaseKey.OpenSubKey("SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client", $true)
                        $TLSClientSubKey.SetValue("DisabledByDefault", "0", [Microsoft.Win32.RegistryValueKind]::DWORD)
                        $TLSClientSubKey.SetValue("Enabled", "1", [Microsoft.Win32.RegistryValueKind]::DWORD)
                        $TLSServerSubKey = $BaseKey.OpenSubKey("SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server", $true)
                        $TLSServerSubKey.SetValue("DisabledByDefault", "0", [Microsoft.Win32.RegistryValueKind]::DWORD)
                        $TLSServerSubKey.SetValue("Enabled", "1", [Microsoft.Win32.RegistryValueKind]::DWORD)

                        Write-Log -String "Updating TLS .NET v4 registry keys on server $Server" -Name $Logname
                        # Have to tell .NET 4.0/4.5 to use TLS 1.2 (I.E. SchUseStrongCrypto) and set System Default TLS to 1.2 (Is required on 2016+ to make TLS 1.2 system default)
                        $DotNetv4BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $Server)
                        $DotNetv4SubKey = $DotNetv4BaseKey.OpenSubKey("SOFTWARE\Microsoft\.NETFramework\v4.0.30319", $true)
                        $DotNetv4SubKey.SetValue("SchUseStrongCrypto", "1", [Microsoft.Win32.RegistryValueKind]::DWORD)
                        $DotNetv4SubKey.SetValue("SystemDefaultTlsVersions", "1", [Microsoft.Win32.RegistryValueKind]::DWORD)

                        Write-Log -String "Updating .NET 32 / 64 bit TLS registry keys" -Name $Logname
                        $Wow6432BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $Server)
                        $Wow32 = $Wow6432BaseKey.OpenSubKey("SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727", $true)
                        $Wow6432 = $Wow6432BaseKey.OpenSubKey("SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319", $true)
                        $Wow32.SetValue("SchUseStrongCrypto", "1", [Microsoft.Win32.RegistryValueKind]::DWORD)
                        $Wow32.SetValue("SystemDefaultTlsVersions", "1", [Microsoft.Win32.RegistryValueKind]::DWORD)
                        $Wow6432.SetValue("SchUseStrongCrypto", "1", [Microsoft.Win32.RegistryValueKind]::DWORD)
                        $Wow6432.SetValue("SystemDefaultTlsVersions", "1", [Microsoft.Win32.RegistryValueKind]::DWORD)
                        Write-Log -String "TLS 1.2 Client / Server and .NET keys should now be updated on $Server" -Name $Logname    
                    }
                    catch {
                        Write-Log -String "Unable to connect to server $Server" -Name $Logname
                        Write-Log -String "Exception encountered $($_.Exception.Message)" -Name $Logname
                        Write-Error $_.Exception.Message
                        Read-Host -Prompt "Hit Enter key to continue"
                    }
             
                }
                else {
                    Write-Log -String "Status code returned something other than zero (success)" -Name $Logname
                    Write-Log -String "Status code returned $($StatusCodes[$ServerCheck.StatusCode])" -Name $Logname
                    Write-Log -String "Unable to continue on server $Server to update TLS registry settings" -Name $Logname
                    Write-Host "Unable to connect to server $Server to update TLS registry settings."
                    Write-Error "Unable to connect to server $Server to update tLS registry settings. " -ErrorAction SilentlyContinue
                }
            }
            # Prompt user how how to proceed after TLS changes.
            Add-Type -AssemblyName PresentationCore, PresentationFramework
            $Button = [System.Windows.MessageBoxButton]::YesNoCancel
            $PopupTitle = "Return to Main Menu?"
            $PopupIcon = [System.Windows.MessageBoxImage]::Question
            $Popupbody = "Would you like to return to the Main Menu?"
    
            $MainMenuResult = [System.Windows.MessageBox]::Show($Popupbody, $PopupTitle, $Button, $PopupIcon)
    
            if ($MainMenuResult -eq "Yes") {
                Write-Log -String "$($ExecutingUser) selected Yes to return to Main Menu" -Name $Logname
                Write-Host " "
                Write-Host "You need to reboot the following servers for the TLS 1.2 settings to take affect"
                Write-Host $ServerNames
                Write-Log -String "Notifying $($ExecutingUser) that servers $ServerNames will need to be rebooted for changes to take effect" -Name $Logname
                Write-Host " "
                Write-Host "No Reboot will be initiated from this utility"
                Write-Host "This is just a reminder that it needs to be completed for changes to take effect."
                Read-Host -Prompt "Hit Enter key to acknowledge"; Clear-Host; Write-Log -String "$($ExecutingUser) hit Enter to acknowledge rebooting is required for changes to take affect" -Name $Logname
                Clear-Host
                Start-Menu
            }
            elseif ($MainMenuResult -eq "No") {
                Write-Log -String "$($ExecutingUser) selected No to return to Main Menu, exiting scipt" -Name $Logname
                Write-Host " "
                Write-Host "You need to reboot the following servers for the TLS 1.2 settings to take affect"
                Write-Host $ServerNames
                Write-Log -String "Notifying $($ExecutingUser) that servers $ServerNames will need to be rebooted for changes to take effect" -Name $Logname
                Write-Host " "
                Write-Host "No Reboot will be initiated from this utility" 
                Write-host "This is just a reminder that it needs to be completed for changes to take affect."
                Read-Host -Prompt "Hit Enter key to acknowledge"; Clear-Host; Write-Log -String "$($ExecutingUser) hit Enter to acknowledge rebooting is required for changes to take affect" -Name $Logname
                Exit
            }
            elseif ($MainMenuResult -eq "Cancel") {
                Write-Log -String "$($ExecutingUser) selected Cancel, exiting scipt" -Name $Logname
                Write-Host " "
                Write-Host "You need to reboot the following servers for the TLS 1.2 settings to take effect"
                Write-Host $ServerNames
                Write-Log -String "Notifying $($ExecutingUser) that servers $ServerNames will need to be rebooted for changes to take affect" -Name $Logname
                Write-Host " "
                Write-Host "No Reboot will be initiated from this utility"
                Write-Host "This is just a reminder that it needs to be completed for changes to take effect."
                Read-Host -Prompt "Hit Enter key to acknowledge"; Clear-Host; Write-Log -String "$($ExecutingUser) hit Enter to acknowledge rebooting is required for changes to take effect" -Name $Logname
                Exit
            }

        }
        else {
            Clear-Host
            Write-Host ""
            Write-Log -String "No server names entered during prompt, unable to continue" -Name $Logname
            Write-Host "No server names entered during prompt, unable to continue" -ForegroundColor Red 
            Write-Error "Unable to continue..." -ErrorAction Stop
        }
        Start-Menu

    }
    elseif ($PopupResult -eq "No") {
        Write-log -String "$($ExecutingUser) Selected No for not wantinig to update additional servers TLS settings." -Name $Logname
        Clear-Host
        Add-Type -AssemblyName PresentationCore, PresentationFramework
        $Button = [System.Windows.MessageBoxButton]::YesNoCancel
        $PopupTitle = "Restart Computer?"
        $PopupIcon = [System.Windows.MessageBoxImage]::Question
        $Popupbody = "Do you want to restart the server for TLS settings to take affect? "
    
        $PopupResult = [System.Windows.MessageBox]::Show($Popupbody, $PopupTitle, $Button, $PopupIcon)
    
        if ($PopupResult -eq "Yes") {
            Write-Log -String "$($ExecutingUser) selected Yes to reboot server" -Name $Logname
            Restart-Computer
        }
        elseif ($PopupResult -eq "No") {
            Write-Log -String "$($ExecutingUser) selected No to restart the server, returning to main menu" -Name $Logname
            Start-Menu
        }
        elseif ($PupupResult -eq "Cancel") {
            Write-Log -String "$($ExecutingUser) selected Cancel, exiting scipt" -Name $Logname
            Exit
        }
    }
    elseif ($PopupResult -eq "Cancel") {
        Write-Log -String "$($ExecutingUser) selected cancel, ending script" -Name $Logname
        exit
    }

}
    # Function for ADFS Azure MFA certificate renewal.
function Update-ADFSServersMFACert {

    begin {
        Write-Log -String "$($ExecutingUser) selected Renew Azure MFA certificate" -Name $Logname
        Clear-Host
        Write-Host ""
        $Tenantid = Read-Host -Prompt "Tenant id Example contoso.onmicrosoft.com"
        Write-Log -String "$($ExecutingUser) entered Tenant id of $Tenantid" -Name $Logname
        try {
            $ExistingMFACert = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object { $_.DnsNameList -contains "$Tenantid" }
            Clear-Host
            if ($ExistingMFACert.count -gt 0) {
                foreach ($MFACert in $ExistingMFACert) {
                    $MultipleExistingCerts = [PSCustomObject]@{
                        Subject    = $MFACert.Subject
                        Thumbprint = $MFACert.Thumbprint
                        Valid      = $MFACert.NotAfter
                    } 
                    Write-Log -String "Existing Certificate found, displaying for $($ExecutingUser) to decide if its expired or not" -Name $Logname
                    foreach ($object in $MultipleExistingCerts) {
                        foreach ($i in $object.PSObject.Properties) {
                            Write-log -String "$($i.Name), $($i.Value)" -Name $Logname
                            Write-Host ""
                            Write-Host "$($i.Name), $($i.Value)"                  
                        }
                    }  
                
                }
           
            }
        }
        catch {
            Write-Log -String "Error encountered checking for previous certificate" -Name $Logname
            Write-Log -String "Exception encountered $($_.Exception.Message)" -Name $Logname
        }
        # Prompt user to confirm certificate is not expired, if its expired let user know a different procedure needs to be run.
        Write-Log -String "Prompting $($ExecutingUser) to verify if the existing certificate is already expired." -Name $Logname     
        Add-Type -AssemblyName PresentationCore, PresentationFramework
        $RenewButton = [System.Windows.MessageBoxButton]::YesNoCancel
        $RenewPopupTitle = "Azure MFA certificates already expired"
        $RenewPopupIcon = [System.Windows.MessageBoxImage]::Question
        $RenewPopupbody = "Is the Azure MFA certificate already expired?"
        $RenewPopupResult = [System.Windows.MessageBox]::Show($RenewPopupbody, $RenewPopupTitle, $RenewButton, $RenewPopupIcon)
    }

    process {
        if ($RenewPopupResult -eq 'Yes') {
            Write-Log -String "$($ExecutingUser) selected Yes to attest that the Azure MFA certificate is already expired" -Name $Logname
            Clear-Host
            Write-Host ""
            Write-Host "You will not be able to renew if your MFA certificate is already expired"
            Write-Host ""
            Write-Host "You will have to delete existing certificates and go through New Azure MFA process"
            Read-Host -Prompt "Hit Enter to reload the menu to select New ADFS Azure MFA Setup"
            Clear-Host
            Start-Menu
        }
        elseif ($RenewPopupResult -eq 'No') {
            Try {
                Write-Log -String "$($ExecutingUser) selected No, Azure MFA certificate as NOT being expired" -Name $Logname
                $newcert = New-AdfsAzureMfaTenantCertificate -TenantId $Tenantid -Renew $true
                Write-Log -String "Generating new certificate using TenantID of $($Tenantid)" -Name $Logname
                Write-Log -String "New certificate details $($newcert)" -Name $Logname
                Write-Log -String "Attempting to connect to MSOL Service" -Name $Logname
                Get-MSOLServiceConnection
            }
            catch {
                Write-Log -String "Unable to connect to MSOnline Service" -Name $Logname
                Write-Log -String "Exception enctountered $($_.Exception.Message)" -Name $Logname
                Write-Error $_.Exception.Message -ErrorAction Stop
            }
            if ($?) {
                Try {
                    Write-Log -String "MSOL Service Connected" -Name $Logname
                    New-MsolServicePrincipalCredential -AppPrincipalId 981f26a1-7f43-403b-a875-f8b09b8cd720 -Type Asymmetric -Usage Verify -Value $newcert
                    Write-Log -String "New MsolServicePrincipalCredential applied, Prompting $($ExecutingUser) to restart ADFS Service" -Name $Logname
                    Restart-ServiceNotification     
     
                }
                catch {
                    Write-Log -String "Failed to upload new Azure MFA certificate" -Name $Logname
                    Write-Log -String "Exception encountered $($_.Exception.Message)" -Name $Logname
                    Write-Error $_.Exception.Message -ErrorAction Stop
                }
            }
            else {
                Write-Log -String "MSOL Service failed to connect" -Name $Logname
                Write-Error "Unable to connect to MSOL Service to upload new MFA Certificate"
                Read-Host -Prompt "Press Enter to Exit"
                Exit
            }
            
        }
        elseif ($RenewPopupresult -eq 'Cancel') {
            Write-Log -String "$($ExecutingUser) selected cancel to restart ADFS service" -Name $Logname
        }
    }
    End {
        Write-Log -String "Ending Restart-ServiceNotification function" -Name $Logname
    }
    
    
}
    # Function to retrieve and delete Azure Multi-Factor Auth Client Service Principals.
function Get-AzureMFAClientCerts {
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
        Write-Log -String "Prompting $($ExecutingUser) for KeyId of Certificate to removed" -Name $Logname
        $KeyId = Read-Host -Prompt "KeyId of Certificate to delete"
        Write-Log -String "$($ExecutingUser) entered KeyId: $($KeyId)" -Name $Logname
        if ($null -ne $KeyId) {
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
            Write-Log -String "KeyId is null, ending script nothing to do" -Name $Logname
            Write-Host ""
            Write-Host "No KeyId enter, ending script as there is nothing to do."
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

Write-Log -String "*********************************************************" -Name $Logname
Write-log -String "*                      START SCRIPT                     *" -Name $Logname
Write-log -String "*********************************************************" -Name $Logname
$ExecutingUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name
Write-Log -String "User Executing Script $($ExecutingUser)" -Name $Logname
function Start-Menu {
    # Init PowerShell Gui
    Write-Log -String "Loading menu of choices for $($ExecutingUser)" -Name $Logname
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    # Create a new form
    [System.Windows.Forms.Application]::EnableVisualStyles()

    $AzureMFAForm = New-Object system.Windows.Forms.Form

    # Define the size, title and background color
    $AzureMFAForm.ClientSize = '500,300'
    $AzureMFAForm.text = "Azure MFA Utility"
    $AzureMFAForm.BackColor = "#ffffff"
    $AzureMFAForm.StartPosition = "CenterScreen"
    $AzureMFAForm.TopMost = $false

    $Font = New-Object System.Drawing.Font("Times New Roman", 11)
    $AzureMFAForm.Font = $Font

    $AzureMFGroup = New-Object System.Windows.Forms.GroupBox
    $AzureMFGroup.Location = '40,30'
    $AzureMFGroup.size = '400,210'
    $AzureMFGroup.Text = "Select an option on how to proceed"

    $Radiobtn1 = New-Object System.Windows.Forms.RadioButton
    $Radiobtn1.Location = '20,40'
    $Radiobtn1.Size = '350,20'
    $Radiobtn1.Checked = $false
    $Radiobtn1.Text = "Check ADFS Azure MFA Prerequisites"

    $Radiobtn2 = New-Object System.Windows.Forms.RadioButton
    $Radiobtn2.Location = '20,70'
    $Radiobtn2.Size = '350,20'
    $Radiobtn2.Checked = $false
    $Radiobtn2.Text = "New ADFS Azure MFA Setup"

    $Radiobtn3 = New-Object System.Windows.Forms.RadioButton
    $Radiobtn3.Location = '20,100'
    $Radiobtn3.Size = '350,20'
    $Radiobtn3.Checked = $false
    $Radiobtn3.Text = "Renew Azure MFA Certificate"

    $Radiobtn4 = New-Object System.Windows.Forms.RadioButton
    $Radiobtn4.Location = '20,130'
    $Radiobtn4.Size = '350,20'
    $Radiobtn4.Checked = $false
    $Radiobtn4.Text = "Fix TLS 1.2 Compliance"

    $Radiobtn5 = New-Object System.Windows.Forms.RadioButton
    $Radiobtn5.Location = '20,160'
    $Radiobtn5.Size = '350,20'
    $Radiobtn5.Checked = $false
    $Radiobtn5.Text = "View and or Clean up Azure MFA Certificates"

    $OKButton = New-Object System.Windows.Forms.Button
    $OKButton.Location = '130,250'
    $OKButton.Size = '100,40'
    $OKButton.Text = 'OK'
    $OKButton.DialogResult = [System.Windows.Forms.DialogResult]::OK

    $CancelButton = New-Object System.Windows.Forms.Button
    $CancelButton.Location = '250,250'
    $CancelButton.Size = '100,40'
    $CancelButton.Text = 'Cancel'
    $CancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel

    $AzureMFGroup.Controls.AddRange(@($Radiobtn1, $Radiobtn2, $Radiobtn3, $Radiobtn4, $Radiobtn5))

    $AzureMFAForm.Controls.AddRange(@($AzureMFGroup, $OKButton, $CancelButton))

    $AzureMFAForm.AcceptButton = $OKButton
    $AzureMFAForm.CancelButton = $CancelButton

    $AzureMFAForm.Add_Shown({ $AzureMFAForm.Activate() })

    $ButtonResult = $AzureMFAForm.ShowDialog()

    if ($ButtonResult -eq "OK") {
        if ($Radiobtn1.Checked -eq $true) { Get-OnPremPreRequisites }
        elseif ($Radiobtn2.Checked -eq $true) { New-MfaCertificate }
        elseif ($Radiobtn3.Checked -eq $true) { Update-ADFSServersMFACert }
        elseif ($Radiobtn4.checked -eq $true) { Update-Tls }
        elseif ($Radiobtn5.Checked -eq $true) { Write-Log -String "$($ExecutingUser) selected View or Clean up Azure MFA Certificates" -Name $Logname; Get-AzureMFAClientCerts }

    }
    else {
        if ($ButtonResult -eq "Cancel") { Clear-Host; Write-Log "$($ExecutingUser) selected Cancel ending application" -Name $Logname; Exit }
    }
    [void]$AzureMFAForm.ShowDialog()
}
Clear-Host
# Load Menu for choices
Start-Menu