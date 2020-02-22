 
$ErrorActionPreference = "Stop"

# The language resources for this script are placed in the
# "Add-AppDevPackage.resources" subfolder alongside the script.  Since the
# current working directory might not be the directory that contains the
# script, we need to create the full path of the resources directory to
# pass into Import-LocalizedData
$ScriptPath = $null
try
{
    $ScriptPath = (Get-Variable MyInvocation).Value.MyCommand.Path
    $ScriptDir = Split-Path -Parent $ScriptPath
}
catch {}

if (!$ScriptPath)
{
    PrintMessageAndExit $UiStrings.ErrorNoScriptPath $ErrorCodes.NoScriptPath
}

Import-LocalizedData -BindingVariable UiStrings -FileName "AddAppxProvisionedPackage.psd1"

$ErrorCodes = Data {
    ConvertFrom-StringData @'
    Success = 0
    NoScriptPath = 1
    NoPackageFound = 2
    ManyPackagesFound = 3
    NoCertificateFound = 4
    ManyCertificatesFound = 5
    BadCertificate = 6
    PackageUnsigned = 7
    CertificateMismatch = 8
    ForceElevate = 9
    LaunchAdminFailed = 10
    GetDeveloperLicenseFailed = 11
    InstallCertificateFailed = 12
    AddPackageFailed = 13
    ForceDeveloperLicense = 14
    CertUtilInstallFailed = 17
    CertIsCA = 18
    BannedEKU = 19
    NoBasicConstraints = 20
    NoCodeSigningEku = 21
    InstallCertificateCancelled = 22
    BannedKeyUsage = 23
    ExpiredCertificate = 24
'@
}

function PrintMessageAndExit($ErrorMessage, $ReturnCode)
{
	$session.Log($ErrorMessage)
    exit $ReturnCode
}

#
# Validates whether a file is a valid certificate using CertUtil.
# This needs to be done before calling Get-PfxCertificate on the file, otherwise
# the user will get a cryptic "Password: " prompt for invalid certs.
#
function ValidateCertificateFormat($FilePath)
{
    # certutil -verify prints a lot of text that we don't need, so it's redirected to $null here
    certutil.exe -verify $FilePath > $null
    if ($LastExitCode -lt 0)
    {
        PrintMessageAndExit ($UiStrings.ErrorBadCertificate -f $FilePath, $LastExitCode) $ErrorCodes.BadCertificate
    }
    
    # Check if certificate is expired
    $cert = Get-PfxCertificate $FilePath
    if (($cert.NotBefore -gt (Get-Date)) -or ($cert.NotAfter -lt (Get-Date)))
    {
        PrintMessageAndExit ($UiStrings.ErrorExpiredCertificate -f $FilePath) $ErrorCodes.ExpiredCertificate
    }
}

#
# Verify that the developer certificate meets the following restrictions:
#   - The certificate must contain a Basic Constraints extension, and its
#     Certificate Authority (CA) property must be false.
#   - The certificate's Key Usage extension must be either absent, or set to
#     only DigitalSignature.
#   - The certificate must contain an Extended Key Usage (EKU) extension with
#     Code Signing usage.
#   - The certificate must NOT contain any other EKU except Code Signing and
#     Lifetime Signing.
#
# These restrictions are enforced to decrease security risks that arise from
# trusting digital certificates.
#
function CheckCertificateRestrictions
{
    Set-Variable -Name BasicConstraintsExtensionOid -Value "2.5.29.19" -Option Constant
    Set-Variable -Name KeyUsageExtensionOid -Value "2.5.29.15" -Option Constant
    Set-Variable -Name EkuExtensionOid -Value "2.5.29.37" -Option Constant
    Set-Variable -Name CodeSigningEkuOid -Value "1.3.6.1.5.5.7.3.3" -Option Constant
    Set-Variable -Name LifetimeSigningEkuOid -Value "1.3.6.1.4.1.311.10.3.13" -Option Constant

    $CertificateExtensions = (Get-PfxCertificate $CertificatePath).Extensions
    $HasBasicConstraints = $false
    $HasCodeSigningEku = $false

    foreach ($Extension in $CertificateExtensions)
    {
        # Certificate must contain the Basic Constraints extension
        if ($Extension.oid.value -eq $BasicConstraintsExtensionOid)
        {
            # CA property must be false
            if ($Extension.CertificateAuthority)
            {
                PrintMessageAndExit $UiStrings.ErrorCertIsCA $ErrorCodes.CertIsCA
            }
            $HasBasicConstraints = $true
        }

        # If key usage is present, it must be set to digital signature
        elseif ($Extension.oid.value -eq $KeyUsageExtensionOid)
        {
            if ($Extension.KeyUsages -ne "DigitalSignature")
            {
                PrintMessageAndExit ($UiStrings.ErrorBannedKeyUsage -f $Extension.KeyUsages) $ErrorCodes.BannedKeyUsage
            }
        }

        elseif ($Extension.oid.value -eq $EkuExtensionOid)
        {
            # Certificate must contain the Code Signing EKU
            $EKUs = $Extension.EnhancedKeyUsages.Value
            if ($EKUs -contains $CodeSigningEkuOid)
            {
                $HasCodeSigningEKU = $True
            }

            # EKUs other than code signing and lifetime signing are not allowed
            foreach ($EKU in $EKUs)
            {
                if ($EKU -ne $CodeSigningEkuOid -and $EKU -ne $LifetimeSigningEkuOid)
                {
                    PrintMessageAndExit ($UiStrings.ErrorBannedEKU -f $EKU) $ErrorCodes.BannedEKU
                }
            }
        }
    }

    if (!$HasBasicConstraints)
    {
        PrintMessageAndExit $UiStrings.ErrorNoBasicConstraints $ErrorCodes.NoBasicConstraints
    }
    if (!$HasCodeSigningEKU)
    {
        PrintMessageAndExit $UiStrings.ErrorNoCodeSigningEku $ErrorCodes.NoCodeSigningEku
    }
}

#
# Checks whether the machine is missing a valid developer license.
#
function CheckIfNeedDeveloperLicense
{
    $Result = $true
    try
    {
        $Result = (Get-WindowsDeveloperLicense | Where-Object { $_.IsValid } | Measure-Object).Count -eq 0
    }
    catch {}

    return $Result
}

#

#
# Finds all applicable dependency packages according to OS architecture, and
# installs the developer package with its dependencies.  The expected layout
# of dependencies is:
#
# <current dir>
#     \Dependencies
#         <Architecture neutral dependencies>.appx
#         \x86
#             <x86 dependencies>.appx
#         \x64
#             <x64 dependencies>.appx
#         \arm
#             <arm dependencies>.appx
#
function InstallPackage($FilePath)
{
    $DependencyPackagesDir = (Join-Path $ScriptDir "Dependencies")
    $DependencyPackages = @()
    if (Test-Path $DependencyPackagesDir)
    {
        # Get architecture-neutral dependencies
        $DependencyPackages += Get-ChildItem (Join-Path $DependencyPackagesDir "*.appx") | Where-Object { $_.Mode -NotMatch "d" }

        # Get architecture-specific dependencies
        if (($Env:Processor_Architecture -eq "x86" -or $Env:Processor_Architecture -eq "amd64") -and (Test-Path (Join-Path $DependencyPackagesDir "x86")))
        {
            $DependencyPackages += Get-ChildItem (Join-Path $DependencyPackagesDir "x86\*.appx") | Where-Object { $_.Mode -NotMatch "d" }
        }
        if (($Env:Processor_Architecture -eq "amd64") -and (Test-Path (Join-Path $DependencyPackagesDir "x64")))
        {
            $DependencyPackages += Get-ChildItem (Join-Path $DependencyPackagesDir "x64\*.appx") | Where-Object { $_.Mode -NotMatch "d" }
        }
        if (($Env:Processor_Architecture -eq "arm") -and (Test-Path (Join-Path $DependencyPackagesDir "arm")))
        {
            $DependencyPackages += Get-ChildItem (Join-Path $DependencyPackagesDir "arm\*.appx") | Where-Object { $_.Mode -NotMatch "d" }
        }
    }

    $AddPackageSucceeded = $False
    try
    {
        if ($DependencyPackages.FullName.Count -gt 0)
        {
            $session.Log( $UiStrings.DependenciesFound)
            $DependencyPackages.FullName
		    $session.Log($UiStrings.InstallingPackage)
		    $session.Log($FilePath)
			Add-AppxProvisionedPackage -Online -PackagePath $FilePath -DependencyPackagePath $DependencyPackages.FullName -SkipLicense
 #           Add-AppxPackage -Path $FilePath -DependencyPath $DependencyPackages.FullName -ForceApplicationShutdown
        }
        else
        {
		    $session.Log($UiStrings.InstallingPackage)
		    $session.Log($FilePath)
			Add-AppxProvisionedPackage -Online -PackagePath $FilePath -SkipLicense
#           Add-AppxPackage -Path $FilePath -ForceApplicationShutdown
        }
        $AddPackageSucceeded = $?
    }
    catch
    {
        $session.Log($Error[0]) # Dump details about the last error
    }

    if (!$AddPackageSucceeded)
    {
        if ($NeedInstallCertificate)
        {
            PrintMessageAndExit $UiStrings.ErrorAddPackageFailedWithCert $ErrorCodes.AddPackageFailed
        }
        else
        {
            PrintMessageAndExit $UiStrings.ErrorAddPackageFailed $ErrorCodes.AddPackageFailed
        }
    }
}

#
# Main script entry point
#
#$session.Log("Installing signed APPX file")

$auAppxFile='AlienwareDigitalDelivery_x64.appxbundle'
$auMssAppxFile='AlienwareDigitalDelivery_x64_MSS.appxbundle'
$auLicenseFile='AlienwareDigitalDelivery_x64.cer'
$auXmlLicenseFile='AlienwareDigitalDelivery_x64.xml'
$duAppxFile='DellDigitalDelivery_x64.appxbundle'
$duMssAppxFile='DellDigitalDelivery_x64_MSS.appxbundle'
$duLicenseFile='DellDigitalDelivery_x64.cer'
$duXmlLicenseFile='DellDigitalDelivery_x64.xml'
$VCLibsFile='Microsoft.VCLibs_x64.appx'
$NETNativeFile='Microsoft.NET.Native.Framework_x64.appx'
$NETRunTimeFile='Microsoft.NET.Native.Runtime.2.0_x64.appx'
#$VCLibs32File='Microsoft.VCLibs_x32.appx'
#$NETNative32File='Microsoft.NET.Native.Framework_x32.appx'
#$NETRunTime32File='Microsoft.NET.Native.Runtime.2.0_x32.appx'

$sdir=split-path -parent $MyInvocation.MyCommand.Definition
$PackagePath=""
#$sdir="C:\D3-9-27\dotnet\tools\DellPreInstallKit"

$computerSystem = Get-CimInstance CIM_ComputerSystem
$manufacturer = $computerSystem.Manufacturer.ToLower()

 $logMessage="Manufacturer detected as:" + $manufacturer
 $session.Log($logMessage)

$VCLibs=Join-Path $sdir -ChildPath $VCLibsFile
$session.Log($UiStrings.PackageFound -f $VCLibs)

$NETNative=Join-Path $sdir -ChildPath $NETNativeFile
$session.Log($UiStrings.PackageFound -f $NETNative)

$NETRuntime=Join-Path $sdir -ChildPath $NETRunTimeFile
$session.Log($UiStrings.PackageFound -f $NETNative)

#$VCLibs32=Join-Path $sdir -ChildPath $VCLibs32File
#$session.Log($UiStrings.PackageFound -f $VCLibs)

#$NETNative32=Join-Path $sdir -ChildPath $NETNative32File
#$session.Log($UiStrings.PackageFound -f $NETNative)

#$NETRuntime32=Join-Path $sdir -ChildPath $NETRunTime32File
#$session.Log($UiStrings.PackageFound -f $NETNative)


if ( $manufacturer.Contains("alienware") )
{
    $logMessage="Alieware system detected - deleting Dell appx files"
    $session.Log($logMessage)

	$PackagePath=Join-Path $sdir -ChildPath $auAppxFile
    $session.Log($UiStrings.PackageFound -f $PackagePath)

	$MssPackagePath=Join-Path $sdir -ChildPath $auMssAppxFile
    $session.Log($UiStrings.PackageFound -f $MssPackagePath)

	$CertificatePath=Join-Path $sdir -ChildPath $NETNativeFile
    $session.Log($UiStrings.CertificateFound -f $CertificatePath)

	$XmlCertificatePath=Join-Path $sdir -ChildPath $auXmlLicenseFile
    $session.Log($UiStrings.CertificateFound -f $CertificatePath)

	# delete the Dell UWP files
	$appxPath=Join-Path $sdir -ChildPath $duAppxFile
    try
    {
        Remove-Item -path $appxPath -recurse
    }
    catch
	{
		$session.Log($UiStrings.ErrorNoPackageFound -f $appxPath)
	}

	$licensePath=Join-Path $sdir -ChildPath $duLicenseFile
    try
    {
		Remove-Item -path $licensePath -recurse
    }
    catch
	{
		$session.Log($UiStrings.ErrorNoPackageFound -f $licensePath)
	}

	$xmllicensePath=Join-Path $sdir -ChildPath $duXmlLicenseFile
    try
    {
		Remove-Item -path $licensePath -recurse
    }
    catch
	{
		$session.Log($UiStrings.ErrorNoPackageFound -f $xmllicensePath)
	}

}
elseif ( $manufacturer.Contains("dell") )
{
    $logMessage="Dell system detected"
    $session.Log($logMessage)

	$PackagePath=Join-Path $sdir -ChildPath $duAppxFile
    $session.Log($UiStrings.PackageFound -f $PackagePath)

	$MssPackagePath=Join-Path $sdir -ChildPath $duMssAppxFile
    $session.Log($UiStrings.PackageFound -f $MssPackagePath)

	$CertificatePath=Join-Path $sdir -ChildPath $duLicenseFile
    $session.Log($UiStrings.CertificateFound -f $CertificatePath)

	$XmlCertificatePath=Join-Path $sdir -ChildPath $duXmlLicenseFile
    $session.Log($UiStrings.CertificateFound -f $CertificatePath)

	# delete the Alienware UWP files
	$appxPath=Join-Path $sdir -ChildPath $auAppxFile
    try
    {
        Remove-Item -path $appxPath -recurse
    }
    catch
	{
		$session.Log($UiStrings.ErrorNoPackageFound -f $appxPath)
	}
	$licensePath=Join-Path $sdir -ChildPath $auLicenseFile
    try
    {
		Remove-Item -path $licensePath -recurse
    }
    catch
	{
		$session.Log($UiStrings.ErrorNoPackageFound -f $licensePath)
	}
	$xmllicensePath=Join-Path $sdir -ChildPath $auXmlLicenseFile
    try
    {
		Remove-Item -path $licensePath -recurse
    }
    catch
	{
		$session.Log($UiStrings.ErrorNoPackageFound -f $xmllicensePath)
	}

}
else
{
    $logMessage="Unknown system manufacturer detected: " + $computerSystem.Manufacturer
	$session.Log($logMessage)
	exit(1)
} 

$IsAlreadyElevated = ([Security.Principal.WindowsIdentity]::GetCurrent().Groups.Value -contains "S-1-5-32-544")
if ($IsAlreadyElevated)
{
			$NeedDeveloperLicense = CheckIfNeedDeveloperLicense
			if ($NeedDeveloperLicense)
			{
				try
				{
					$session.Log("System does not have developer license - doing Dism.exe install")
					try
					{
						$version = "DellInc.DellDigitalDelivery_" + $Args[0] + "_neutral_~_htrsf667h5kn2"
						$session.Log($version)

						$session.Log("Attempting to remove provisioned package if same version")
                        $removeCommand = {param($version) dism.exe /online /Remove-ProvisionedAppxPackage /PackageName:$version}
                        $job = Start-Job -ScriptBlock $removeCommand -ArgumentList $version
                        Wait-Job $job
                        Receive-Job $job					
					}
					catch {}

					$session.Log("Adding provisioned package")
					$insCommand = {param($MssPackagePath,$VCLibs,$NETNative,$NETRuntime,$XmlCertificatePath) dism.exe /online /Add-ProvisionedAppxPackage /PackagePath:$MssPackagePath /DependencyPackagePath:$VCLibs /DependencyPackagePath:$NETNative /DependencyPackagePath:$NETRuntime /LicensePath:$XmlCertificatePath}
                    $job = Start-Job -ScriptBlock $insCommand -ArgumentList $MssPackagePath, $VCLibs, $NETNative, $NETRuntime, $XmlCertificatePath
                    Wait-Job $job
                    Receive-Job $job
                    					
					$session.Log("Adding package for user")
					Add-AppPackage -Path "$MssPackagePath"
				}
				catch {}
			}
			else
			{
				$session.Log("System has a developer license - side-loading")

				# The package must be signed
				$PackageSignature = Get-AuthenticodeSignature $PackagePath
				$PackageCertificate = $PackageSignature.SignerCertificate
				if (!$PackageCertificate)
				{
					PrintMessageAndExit $UiStrings.ErrorPackageUnsigned $ErrorCodes.PackageUnsigned
				}

				# Test if the package signature is trusted.  If not, the corresponding certificate
				# needs to be present in the current directory and needs to be installed.
				$NeedInstallCertificate = ($PackageSignature.Status -ne "Valid")

				if ($NeedInstallCertificate)
				{
					# The .cer file must have the format of a valid certificate
					ValidateCertificateFormat $CertificatePath

					# The package signature must match the certificate file
					if ($PackageCertificate -ne (Get-PfxCertificate $CertificatePath))
					{
						PrintMessageAndExit $UiStrings.ErrorCertificateMismatch $ErrorCodes.CertificateMismatch
					}

					# Make sure certificate format is valid and usage constraints are followed
					ValidateCertificateFormat $CertificatePath
					CheckCertificateRestrictions

					# Import the certificate to Trusted People
					try
					{
						Import-Certificate -FilePath $CertificatePath -CertStoreLocation "Cert:\LocalMachine\TRUSTEDPEOPLE"
						$NeedInstallCertificate = $False
						$session.Log( $UiStrings.InstallCertificateSuccessful)
					}
					catch
					{
						PrintMessageAndExit ($UiStrings.ErrorInstallCertificateFailed -f $Signature.Status) $ErrorCodes.InstallCertificateFailed
					}
				}

				# Install appx package
				InstallPackage $PackagePath
			}
}
else
{
            PrintMessageAndExit $UiStrings.ErrorForceElevate $ErrorCodes.ForceElevate
}






