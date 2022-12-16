# AzureMFACertUtil

This utility will allow you to view, and remove certificates that are uploaded to the Azure Multi-Factor Auth Client Service.
Normally it lists the certificates encoded in Base64 format. This utility will provide the same data as default, but will include
human readable data such as the Subject and Thumbprint of the certificates so that decisions regarding the certificates can be made 
with a clear understanding of what the certificate belongs too.

Azure MFA Service Principals returned before utility:

![BeforeUtility](https://user-images.githubusercontent.com/55394498/208113705-d2839cfb-1937-4257-a8c4-d1d70b77096f.jpg)

After AzureMFACertUtil has been used to retrieve the Multi-Factor Certificates:

![AfterUtility](https://user-images.githubusercontent.com/55394498/208116764-22f7c183-ea49-427c-b83a-55951bd7b7d1.jpg)

# Operation

When the script is executed you will be presented with a popup window like this:
![Selection](https://user-images.githubusercontent.com/55394498/208142057-2341d869-bfd9-4056-9c90-d9330d88ba1c.png)

You have two options.
Retrieve Current Azure MFA Certificates
or
Delete Azure MFA Certificates.

The first option will then prompt you to log into your tenant and then pull the current certificates.
It will then ask you if you would like to delete any certificates. Yes or No.
If you select Yes it will then ask how you would like to delete them. Automatically or Manually.

# WARNING
Automatically will delete ANY certificate that is currently expired. This can break your environment (Azure MFA or NPS)
if you are not sure what you are doing. It will prompt you to ask if you are absolutely sure that you would like to proceed.
If so, it will then cycle through all of the certificates in your tenant and delete any and every certificate that is
currently expired. If you select No, it will go through a manual approach, list all of the certificates and prompt you to
enter the KeyId of a certificate you would like to delete.

Be very careful with the automatic function. I included it mostly for large environments who could potentially have
100s of certificates and doing that manually can be tedious
