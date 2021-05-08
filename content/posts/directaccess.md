+++
title = "DirectAccess with ECDSA certificates"
date = "2021-05-10"
draft = true
categories = ["ECDSA", "PowerShell", "Windows"]
+++

By default when configuring [DirectAccess](https://docs.microsoft.com/en-us/windows-server/remote/remote-access/directaccess/directaccess) it will only accept client certificates that have an RSA key.

{{< highlight powershell >}}
> Import-Module -Force .\directaccess.psm1
> Set-NetIPsecPhase1AuthSetAlgorithms -Authority "C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert Assured ID Root CA" -Algorithm "RSA","ECDSA256"
{{< / highlight >}}

{{< readfile file="static/code/directaccess.ps1" highlight="powershell" >}}  

