Writemeupdac exploits windows services that have WRITE_DAC privilege for a user/group that the attacker controls. The following is the help menu:
```
Check for writedac:
.\<binary name> check

Write DACL to service:
.\<binary name> write <service> [Username/GroupName]

Start Service:
.\<binary name> start <service>

Stop Service:
.\<binary name> stop <service>

Change Binary path for service:
.\<binary name> changebinary <service> <payload>

Auto Exploit Service:
.\<binary name> exploit <service> <payload> [Username/GroupName]

Exploit will change the Authenticated Users group DACL permissions by default, you can specify another SID to modify or add, it will stop the service, modify the binary path, and start the service.

Exploit will not stop any dependent services. Use the stop command to stop the dependant services.

If you intend to change a dacl for a user or group, be absolutely sure the user/group exits and is spelled correctly. Otherwise, the DACLs for the service will be completely removed with no dacls remaining.
```
#Notes:

The check command is currently show some false positives for fully exploitable services such as AppXSvc. Will look into later.

Before specifying a group or user other than Authenticated Users to change dacls on, run in a test environment first. Have not tested with AD accounts and groups yet. If the program cannot find the user or group, when it changes the dacls for the service all the dacls on the service will be removed and there will not be any dacls left on the service besides the SACLs.

I am not be liable for damages or losses arising from your use of this tool.


