# Security Manager
In OpenBMC, AtScaleDebug (ASD) feature should be enabled only by special user
when RemoteDebug feature is enabled in platform. Administrator need to know
whenever ASD feature/special user is enabled or disabled.
Existing OpenBMC will start always the ASD server without verifying the
RemoteDebug Enable jumper and special user password status.
and also, all user account and BMC access should be controlled securely.
so we are not provided any interface to change the password storing
hash algorithm from SHA256/ SHA512 to the weak hash algorithm MD5 or other
remote SSH login, no user is allowed in root privilege. but
If any of above intrusion or non-allowable configuration are done by some means
then BMC must detect and log the security event.

## Background and References
BMC must stop the ASD server service if special user password is disabled.
OpenBMC is not logging the Redfish Event for any ASD activity.

## Requirements
BMC should detect the below intrusion and log the detailed security event.
 1.ASD server shall not allow user credentials provisioned for out-of-band IPMI
 to authenticate over the ASD network interface.
 2.ASD server should use the special User id to authenticate the ASD connection.
 3.ASD server should be disabled when ASD special User has a Null password.
 4.The BMC shall provide command over in-band interface to set the password
 for ASD Dedicated User.
 5.This command shall be blocked over the out-of-band interfaces.
 6.Restart ASD server when the password changes from Null to Non-Null password
 7.Stop ASD server when the password changes from Non-Null to Null password.
 8.BMC monitor "RemoteDebug" jumper GPIO and log event when position is changed.
 9.Log the ASD session event when a remote session is connected/disconnected.
 
 BMC should detect the following intrusion or non-allowed configuration and
 log the security event with description.
 1. Password storing hash algorithm changes from SHA2-256 to MD5 in passwd file
 2. When any user other than root has its UID set to 0 in passwd file
 3. When any unsupported shells (not bash or sh) are present in passwd file
 4. When the root user is assigned a password in passwd file
 
## ASD Security Manager Events

Below Redfish Event logged whenever remote debug on jumper is set.
MessageEntry
{
    "AtScaleDebugFeatureEnabledAtHardware",
    {
        .description =
            "Indicates that At-Scale Debug enable is detected in hardware"
                .message = "At-Scale Debug Feature is enabled in Hardware.",
        .severity = "Critical", .resolution = "None.",
    }
}

Below Redfish Event logged whenever remote debug on jumper is cleared /
    disabled.MessageEntry
{
    "AtScaleDebugFeatureDisabledAtHardware",
    {
        .description =
            "Indicates that At-Scale Debug disable is detected in hardware",
        .message = "At-Scale Debug feature is disabled in hardware.",
        .severity = "OK", .resolution = "None.",
    }
}

Below Redfish Event logged whenever At -
    Scale Debug service is started.MessageEntry
{
    "At-ScaleDebugFeatureEnabled",
    {
        .description = "Indicates that At-Scale Debug service is started",
        .message = "At-Scale Debug service is started.", .severity = "Critical",
        .resolution = "None.",
    }
}

Below Redfish Event logged whenever At -
    Scale Debug service is stopped.MessageEntry
{
    "At-ScaleDebugFeatureDisabled",
    {
        .description = "Indicates that At-Scale Debug service is stopped",
        .message = "At-Scale Debug service is stopped.", .severity = "OK",
        .resolution = "None.",
    }
}

Below Redfish Event logged whenever At -
    Scale Debug connection established.MessageEntry
{
    "AtScaleDebugConnected",
    {
        .description =
            "Indicates At-Scale Debug connection has been established",
        .message = "At-Scale Debug service is now connected %1",
        .severity = "Critical", .args = {"string"}, .resolution = "None.",
    }
}

Below Redfish logged whenever At - Scale Debug connection is closed.MessageEntry
{
    "AtScaleDebugDisconnected",
    {
        .description = "Indicates At-Scale Debug connection has ended",
        .message = "At-Scale Debug service is now disconnected",
        .severity = "OK", .resolution = "None.",
    }
}

Below Redfish logged whenever At - Scale Debug connection error or
    abort.MessageEntry
{
    "AtScaleDebugConnectionFailed",
    {
        .description = "Indicates At-Scale Debug connection aborted/failed",
        .message = "At-Scale Debug connection aborted/failed",
        .severity = "Critical", .resolution = "None.",
    }
}

Below Redfish Event logged whenever At -
    Scale Debug special user is enabled.MessageEntry
{
    "AtScaleDebugSpecialUserEnabled",
    {
        .description = "Indicates that special user is enabled.",
        .message = "At-Scale Debug special user is enabled",
        .severity = "Critical", .resolution = "None.",
    }
}

Below Redfish Event logged whenever At -
    Scale Debug special user is disabled.MessageEntry
{
    "AtScaleDebugSpecialUserDisabled",
    {
        .description = "Indicates that special user is disabled.",
        .message = "At-Scale Debug special user is disabled", .severity = "OK",
        .resolution = "None.",
    }
}

##User Security Events

Note : security event list is maintained in volatile memory.

When SHA256/ 512 hash algorithm is enabled,
    below Redfish Event will be logged.MessageEntry
{
    "SecurityUserHashAlgoChanged",
    {
        .description =
            "Indicates that password computing hash algorithm changed.",
        .message =
            "Password computing hash algorithm is changed to SHA256/SHA512.",
        .severity = "OK", .resolution = "None.",
    }
}

When userid = 0 is assigned to non - root user,
     below Redfish Event will be logged.MessageEntry
{
    "SecurityUserNonRootUidZeroAssigned",
    {
        .description =
            "Indicates that non root user assigned with user id zero.",
        .message = "User id Zero is assigned with non-root user",
        .severity = "Critical", .resolution = "None.",
    }
}

When userid = 0 non root user is removed,
     below Redfish Event will be logged.MessageEntry
{
    "SecurityUserNonRootUidZeroRemoved",
    {
        .description = "Indicates that non root user id is removed",
        .message = "Non root user assigned with user id zero is removed.",
        .severity = "OK", .resolution = "None.",
    }
}

When root user is enabled, below Redfish Event will be logged.MessageEntry
{
    "SecurityUserRootEnabled",
    {
        .description = "Indicates that system root user is enabled.",
        .message = "User root is enabled.", .severity = "Critical",
        .resolution = "None.",
    }
}

When root user is disabled, below Redfish Event will be logged.MessageEntry
{
    "SecurityUserRootDisabled",
    {
        .description = "Indicates that system root user is disabled.",
        .message = "User root is disabled.", .severity = "OK",
        .resolution = "None.",
    }
}

When unsupported shell is enabled,
    below Redfish Event will be logged.MessageEntry
{
    "SecurityUserUnsupportedShellEnabled",
    {
        .description = "Indicates that other than(sh/bash)shell is enabled.",
        .message = "Unsupported(other than sh/bash) shell is enabled",
        .severity = "Critical", .resolution = "None.",
    }
}

When unsupported shell is removed,
    below Redfish Event will be logged.MessageEntry{
        "SecurityUserUnsupportedShellRemoved",
        {
            .description = "Indicates that unsupported shell is removed.",
            .message = "Unsupported shell is removed",
            .severity = "OK",
            .resolution = "None.",
        }},

When weak hash algorithm is enabled,
    below Redfish Event will be logged.MessageEntry{
        "SecurityUserWeakHashAlgoEnabled",
        {
            .desc = "Indicates that pwd hash algo other than SHA256/512 is "
                    "enabled.",
            .message = "Weak password computing hash algorithm is enabled",
            .severity = "Critical",
            .resolution = "None.",
        }},

## Dependency
security manager have following compile dependencies
* sdbusplus
* gpiodcxx
* systemd
* boost

Runtime dependency to maintain FIPS status
* openssl (with fips module)

## Compilation
```
mkdir build
cd build
cmake ../
make
```
## FIPS
Following interfaces are exposed for controlling openssl mode

| Interface  | method/property | details                        | 
| ------------- | ------------- | ------------------------------ |
| com.intel.fips.mode  | DisableFips  | This method disables fips mode in BMC |
| com.intel.fips.mode  | EnableFips   | This method enables FIPS mode. It takes fips provider version number as string arguemnt |
| com.intel.fips.providers  |  AvailableProviders  | property showing list of available FIPS providers. This is argument to EnableFips method |
| com.intel.fips.status  | Enabled  | property showing if FIPS mode is enabled |
| com.intel.fips.status  | Version  | Version of FIPS provider that is under use. This is NA if FIPS is not enabled |

method/property names prefixed with com.intel.fips control openssl configuration to do desired action mentioned in above table.

REMOTE_DEBUG_ENABLE gpio line is used for controlling at scale debug service. This GPIO is active high. At scale debug service will be enabled if REMOTE_DEBUG_ENABLE is high and disabled otherwise.
