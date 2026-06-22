/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2019 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/
   
#include "ssp_global.h"
#include "stdlib.h"
#include "ccsp_dm_api.h"
#include "harvester.h"
#include "ccsp_harvesterLog_wrapper.h"
#include <sysevent/sysevent.h>
#include <math.h>
#include <syscfg/syscfg.h>

#include "libparodus.h"
#include "webpa_interface.h"
#include "safec_lib_common.h"
#include "harvester_avro.h"

#define MAX_PARAMETERNAME_LEN   512
#define ETH_WAN_STATUS_PARAM "Device.Ethernet.X_RDKCENTRAL-COM_WAN.Enabled"
#define RDKB_ETHAGENT_COMPONENT_NAME                  "com.cisco.spvtg.ccsp.ethagent"
#define RDKB_ETHAGENT_DBUS_PATH                       "/com/cisco/spvtg/ccsp/ethagent"

extern ANSC_HANDLE bus_handle;
pthread_mutex_t webpa_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t device_mac_mutex = PTHREAD_MUTEX_INITIALIZER;

char deviceMAC[32]={'\0'};
STATIC void checkComponentHealthStatus(char * compName, char * dbusPath, char *status, int *retStatus, int status_size);
STATIC void waitForEthAgentComponentReady();
STATIC int check_ethernet_wan_status();

libpd_instance_t client_instance;
STATIC void *handle_parodus();

int s_sysevent_connect (token_t *out_se_token);

#define CCSP_AGENT_WEBPA_SUBSYSTEM         "eRT."


/* retrieve the CCSP Component name and path who supports specified name space */
BOOL Cosa_FindDestComp(char* pObjName,char** ppDestComponentName, char** ppDestPath)
{
        int                         ret;
        int                         size = 0;
        componentStruct_t **        ppComponents = NULL;
        char dst_pathname_cr[256] = {0};
        errno_t rc = -1;

        rc = sprintf_s(dst_pathname_cr,sizeof(dst_pathname_cr),"%s%s", CCSP_AGENT_WEBPA_SUBSYSTEM, CCSP_DBUS_INTERFACE_CR);
        if(rc < EOK)
        {
          ERR_CHK(rc);
          return FALSE;
        }
		

        ret = CcspBaseIf_discComponentSupportingNamespace(bus_handle,
                                dst_pathname_cr,
                                pObjName,
                                "",        /* prefix */
                                &ppComponents,
                                &size);

        if ( ret == CCSP_SUCCESS && size >= 1)
        {
                *ppDestComponentName = AnscCloneString(ppComponents[0]->componentName);
                *ppDestPath    = AnscCloneString(ppComponents[0]->dbusPath);

        	free_componentStruct_t(bus_handle, size, ppComponents);
                return  TRUE;
        }
        else
        {
                return  FALSE;
        }
}

void sendWebpaMsg(char *serviceName, char *dest, char *trans_id, char *contentType, char *payload, unsigned int payload_len)
{
    wrp_msg_t *wrp_msg ;
    int retry_count = 0, backoffRetryTime = 0, c = 2;
    int sendStatus = -1;
    char source[MAX_PARAMETERNAME_LEN/2] = {'\0'};
    errno_t rc = -1;

    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s ENTER\n", __FUNCTION__ ));
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, <======== Start of sendWebpaMsg =======>\n"));
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, deviceMAC *********:%s\n",deviceMAC));
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, serviceName :%s\n",serviceName));
    rc = sprintf_s(source,sizeof(source),"mac:%s/%s", deviceMAC, serviceName);
    if(rc < EOK)
    {
      ERR_CHK(rc);
      return;
    }
	if(dest!= NULL){
    	CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, dest :%s\n",dest));
	}
	if(trans_id!= NULL){
	    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, trans_id :%s\n",trans_id));
	}
	if(contentType!= NULL){
	    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, contentType :%s\n",contentType));
    }
	CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, payload_len :%d\n",payload_len));
	if(payload!= NULL){
    	CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, payload :%s\n",payload));
	}
    

    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Received DeviceMac from Atom side: %s\n",deviceMAC));
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Source derived is %s\n", source));
    
    wrp_msg = (wrp_msg_t *)malloc(sizeof(wrp_msg_t));
    

    if(wrp_msg != NULL)
    {
        rc = memset_s(wrp_msg,sizeof(wrp_msg_t),0,sizeof(wrp_msg_t));
        ERR_CHK(rc);
        wrp_msg->msg_type = WRP_MSG_TYPE__EVENT;
        wrp_msg->u.event.payload = (void *)payload;
        wrp_msg->u.event.payload_size = payload_len;
        wrp_msg->u.event.source = source;
        wrp_msg->u.event.dest = dest;
        wrp_msg->u.event.content_type= contentType;

        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, wrp_msg->msg_type :%d\n",wrp_msg->msg_type));
        if(wrp_msg->u.event.payload!=NULL)
        	CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, wrp_msg->u.event.payload :%s\n",(char *)(wrp_msg->u.event.payload)));
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, wrp_msg->u.event.payload_size :%lu\n",(ULONG)wrp_msg->u.event.payload_size));
		if(wrp_msg->u.event.source!=NULL)
        	CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, wrp_msg->u.event.source :%s\n",wrp_msg->u.event.source));
		if(wrp_msg->u.event.dest!=NULL)
        	CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, wrp_msg->u.event.dest :%s\n",wrp_msg->u.event.dest));
		if(wrp_msg->u.event.content_type!=NULL)
	        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, wrp_msg->u.event.content_type :%s\n",wrp_msg->u.event.content_type));

        while(retry_count<=5)
        {
	        backoffRetryTime = (int) pow(2, c) -1;

	        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, retry_count : %d\n",retry_count));
		pthread_mutex_lock(&webpa_mutex);
	        sendStatus = libparodus_send(client_instance, wrp_msg);
		pthread_mutex_unlock(&webpa_mutex);
	        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, sendStatus is %d\n",sendStatus));
	        if(sendStatus == 0)
	        {
	             retry_count = 0;
	             CcspHarvesterTrace(("RDK_LOG_INFO, Sent message successfully to parodus\n"));
	             break;
	        }
	        else
	        {
                CcspHarvesterTrace(("RDK_LOG_ERROR, Failed to send message: '%s', retrying ....\n",libparodus_strerror(sendStatus)));
                CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, backoffRetryTime %d seconds\n", backoffRetryTime));
                sleep(backoffRetryTime);
                c++;
                retry_count++;
	        }
        }

        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Before freeing wrp_msg\n"));
        free(wrp_msg);
        CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, After freeing wrp_msg\n"));
    }

    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG,  <======== End of sendWebpaMsg =======>\n"));

    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s EXIT\n", __FUNCTION__ ));

}

void initparodusTask()
{
    int err = 0;
    pthread_t parodusThreadId;

    err = pthread_create(&parodusThreadId, NULL, handle_parodus, NULL);
    if (err != 0) 
    {
        CcspHarvesterConsoleTrace(("RDK_LOG_ERROR, Error creating messages thread :[%s]\n", strerror(err)));
    }
    else
    {
        CcspHarvesterConsoleTrace(("RDK_LOG_INFO, handle_parodus thread created Successfully\n"));
    }
}

STATIC void *handle_parodus()
{
    int backoffRetryTime = 0;
    int backoff_max_time = 9;
    int max_retry_sleep;
    //Retry Backoff count shall start at c=2 & calculate 2^c - 1.
    int c =2;
	int retval=-1;
	char *parodus_url = NULL;

    CcspHarvesterConsoleTrace(("RDK_LOG_INFO, ******** Start of handle_parodus ********\n"));

    pthread_detach(pthread_self());

    max_retry_sleep = (int) pow(2, backoff_max_time) -1;
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, max_retry_sleep is %d\n", max_retry_sleep ));

    CcspHarvesterConsoleTrace(("RDK_LOG_INFO, Call parodus library init api \n"));

        get_parodus_url(&parodus_url);
	if(parodus_url != NULL)
	{
		libpd_cfg_t cfg1 = {.service_name = "harvester",
						.receive = false, .keepalive_timeout_secs = 0,
						.parodus_url = parodus_url,
						.client_url = NULL
					   };
		            
		CcspHarvesterConsoleTrace(("RDK_LOG_INFO, Configurations => service_name : %s parodus_url : %s client_url : %s\n", cfg1.service_name, cfg1.parodus_url, (cfg1.client_url) ? cfg1.client_url : "" ));
		   
		while(1)
		{
		    if(backoffRetryTime < max_retry_sleep)
		    {
		        backoffRetryTime = (int) pow(2, c) -1;
		    }

		    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, New backoffRetryTime value calculated as %d seconds\n", backoffRetryTime));
		    int ret =libparodus_init (&client_instance, &cfg1);
		    CcspHarvesterConsoleTrace(("RDK_LOG_INFO, ret is %d\n",ret));
		    if(ret ==0)
		    {
		        CcspHarvesterTrace(("RDK_LOG_INFO, Init for parodus Success..!!\n"));
		        break;
		    }
		    else
		    {
		        CcspHarvesterTrace(("RDK_LOG_ERROR, Init for parodus (url %s) failed: '%s'\n", parodus_url, libparodus_strerror(ret)));
                        /* CID: 67436 Logically dead code - 
                           Remove the check  NULL == parodus_url*/
		        sleep(backoffRetryTime);
		        c++;
		    }
		retval = libparodus_shutdown(client_instance);
		    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, libparodus_shutdown retval: %d\n", retval));
		}
	}
    return 0;
}

const char *rdk_logger_module_fetch(void)
{
    return "LOG.RDK.Harvester";
}

STATIC void waitForEthAgentComponentReady()
{
    char status[32] = {'\0'};
    int count = 0;
    int ret = -1;
    errno_t rc = -1;
    int ind = -1;
    int status_len = strlen("Green");
	int health_status = -1;
    while(1)
    {
        checkComponentHealthStatus(RDKB_ETHAGENT_COMPONENT_NAME, RDKB_ETHAGENT_DBUS_PATH, status,&ret,sizeof(status));
        if(ret == CCSP_SUCCESS)
        {
		   rc = strcmp_s("Green", status_len, status , &ind);
		   ERR_CHK(rc);
           if((ind == 0) && (rc == EOK))
               health_status = 1 ;
        }

        if(health_status == 1)
        {
            CcspHarvesterTrace(("RDK_LOG_INFO, %s component health is %s, continue\n", RDKB_ETHAGENT_COMPONENT_NAME, status));
            break;
        }
        else
        {
            count++;
            if(count > 60)
            {
                CcspHarvesterTrace(("RDK_LOG_ERROR, %s component Health check failed (ret:%d), continue\n",RDKB_ETHAGENT_COMPONENT_NAME, ret));
                break;
            }
            if(count%5 == 0)
            {
                CcspHarvesterTrace(("RDK_LOG_ERROR, %s component Health, ret:%d, waiting\n", RDKB_ETHAGENT_COMPONENT_NAME, ret));
            }
            sleep(5);
        }
    }
}

STATIC void checkComponentHealthStatus(char * compName, char * dbusPath, char *status, int *retStatus,int status_size)
{
	int ret = 0, val_size = 0;
	parameterValStruct_t **parameterval = NULL;
	char tmp[MAX_PARAMETERNAME_LEN];
	char *parameterNames[1] = { tmp };
	char str[MAX_PARAMETERNAME_LEN/2];
    errno_t rc = -1;

    rc = sprintf_s(tmp,sizeof(tmp),"%s.%s",compName, "Health");
    if(rc < EOK)
    {
      ERR_CHK(rc);
      *retStatus = CCSP_FAILURE;
      return;
    }

    rc = sprintf_s(str,sizeof(str),"eRT.%s", compName);
    if(rc < EOK)
    {
      ERR_CHK(rc);
      *retStatus = CCSP_FAILURE;
      return;
    }
	CcspHarvesterTrace(("RDK_LOG_DEBUG, str is:%s\n", str));

	ret = CcspBaseIf_getParameterValues(bus_handle, str, dbusPath,  parameterNames, 1, &val_size, &parameterval);
	CcspHarvesterTrace(("RDK_LOG_DEBUG, ret = %d val_size = %d\n",ret,val_size));
	if(ret == CCSP_SUCCESS)
	{
		CcspHarvesterTrace(("RDK_LOG_DEBUG, parameterval[0]->parameterName : %s parameterval[0]->parameterValue : %s\n",parameterval[0]->parameterName,parameterval[0]->parameterValue));
        rc = strcpy_s(status,status_size,parameterval[0]->parameterValue);
        if(rc != EOK)
        {
          ERR_CHK(rc);
          *retStatus = CCSP_FAILURE;
          free_parameterValStruct_t (bus_handle, val_size, parameterval);
          return;
        }

		CcspHarvesterTrace(("RDK_LOG_DEBUG, status of component:%s\n", status));
	}
	free_parameterValStruct_t (bus_handle, val_size, parameterval);

	*retStatus = ret;
}

STATIC int check_ethernet_wan_status()
{
    int ret = -1, size =0, val_size =0;
    char compName[MAX_PARAMETERNAME_LEN/2] = { '\0' };
    char dbusPath[MAX_PARAMETERNAME_LEN/2] = { '\0' };
    parameterValStruct_t **parameterval = NULL;
    char *getList[] = {ETH_WAN_STATUS_PARAM};
    componentStruct_t **        ppComponents = NULL;
    char dst_pathname_cr[256] = {0};
    char isEthEnabled[64]={'\0'};
    errno_t rc = -1;
    int is_WAN_Enabled = -1;
    int ind = -1;
    
    if (( 0 == syscfg_get( NULL, "eth_wan_enabled", isEthEnabled, sizeof(isEthEnabled))) && (isEthEnabled[0] != '\0' ) )
        {
           rc = strcmp_s("true", strlen("true"),isEthEnabled,&ind);
           ERR_CHK(rc);
           if ((ind == 0) && (rc == EOK))
           {
              CcspHarvesterTrace(("RDK_LOG_INFO, Ethernet WAN is enabled\n")); 
              ret = CCSP_SUCCESS;
           } 			  
        }
    else
    {
        waitForEthAgentComponentReady();

        rc = sprintf_s(dst_pathname_cr,sizeof(dst_pathname_cr),"eRT.%s", CCSP_DBUS_INTERFACE_CR);
        if(rc < EOK)
        {
           ERR_CHK(rc);
           return CCSP_FAILURE;
        }
		
        ret = CcspBaseIf_discComponentSupportingNamespace(bus_handle, dst_pathname_cr, ETH_WAN_STATUS_PARAM, "", &ppComponents, &size);
        if ( ret == CCSP_SUCCESS && size >= 1)
        {
            rc = strcpy_s(compName,sizeof(compName),ppComponents[0]->componentName);
            if(rc != EOK)
            {
              ERR_CHK(rc);
              free_componentStruct_t(bus_handle, size, ppComponents);
              return CCSP_FAILURE;
            }

            rc = strcpy_s(dbusPath,sizeof(dbusPath),ppComponents[0]->dbusPath);
            if(rc != EOK)
            {
              ERR_CHK(rc);
              free_componentStruct_t(bus_handle, size, ppComponents);
              return CCSP_FAILURE;
            }

        }
        else
        {
            CcspHarvesterTrace(("RDK_LOG_ERROR, Failed to get component for %s ret: %d\n",ETH_WAN_STATUS_PARAM,ret));
        }
        free_componentStruct_t(bus_handle, size, ppComponents);

        if(strlen(compName) != 0 && strlen(dbusPath) != 0)
        {
            ret = CcspBaseIf_getParameterValues(bus_handle, compName, dbusPath, getList, 1, &val_size, &parameterval);
            if(ret == CCSP_SUCCESS && val_size > 0)
            {
                if(parameterval[0]->parameterValue != NULL )
                {
                    rc = strcmp_s("true", strlen("true"),parameterval[0]->parameterValue,&ind);
                    ERR_CHK(rc);
                    if( (ind == 0) && (rc == EOK))
                    {
                      is_WAN_Enabled = 1 ;
                    }
                }

                if( is_WAN_Enabled == 1 )
                {
                   CcspHarvesterTrace(("RDK_LOG_INFO, Ethernet WAN is enabled\n"));
                   ret = CCSP_SUCCESS;
                }
                else
                {
                   CcspHarvesterTrace(("RDK_LOG_INFO, Ethernet WAN is disabled\n"));
                   ret = CCSP_FAILURE;
                }

            }
            else
            {
                CcspHarvesterTrace(("RDK_LOG_ERROR, Failed to get values for %s ret: %d\n",getList[0],ret));
            }
            free_parameterValStruct_t(bus_handle, val_size, parameterval);
        }
    }
    return ret;
}

char * getDeviceMac()
{
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s ENTER\n", __FUNCTION__ ));

    while(!strlen(deviceMAC))
    {
        int ret = -1, val_size =0,cnt =0, fd = 0;
        parameterValStruct_t **parameterval = NULL;
	char* dstComp = NULL, *dstPath = NULL;
#if defined(_COSA_BCM_MIPS_)
	char getList[256] = "Device.DPoE.Mac_address";
	char* getList1[] = {"Device.DPoE.Mac_address"};
#else
#if defined (_HUB4_PRODUCT_REQ_) || defined(_SR300_PRODUCT_REQ_) || defined(_SCER11BEL_PRODUCT_REQ_) || defined(_SCXF11BFL_PRODUCT_REQ_)
        char getList[256] = "Device.DeviceInfo.X_COMCAST-COM_WAN_MAC";
        char* getList1[] = {"Device.DeviceInfo.X_COMCAST-COM_WAN_MAC"};
#elif defined(PON_GATEWAY)  /* PON/Fiber based gateways needs to be use Device.DeviceInfo.X_COMCAST-COM_WAN_MAC */
        char getList[256] = "Device.DeviceInfo.X_COMCAST-COM_WAN_MAC";
        char* getList1[] = {"Device.DeviceInfo.X_COMCAST-COM_WAN_MAC"};
#else
        char getList[256] = "Device.X_CISCO_COM_CableModem.MACAddress";
        char* getList1[] = {"Device.X_CISCO_COM_CableModem.MACAddress"};
#endif
#endif /*_COSA_BCM_MIPS_*/
        token_t  token;
        char deviceMACValue[32] = { '\0' };

        if (strlen(deviceMAC))
        {
            break;
        }

        fd = s_sysevent_connect(&token);
        if(CCSP_SUCCESS == check_ethernet_wan_status() && sysevent_get(fd, token, "eth_wan_mac", deviceMACValue, sizeof(deviceMACValue)) == 0 && deviceMACValue[0] != '\0')
        {
	    pthread_mutex_lock(&device_mac_mutex);	
            AnscMacToLower(deviceMAC, deviceMACValue, sizeof(deviceMAC));
	    pthread_mutex_unlock(&device_mac_mutex);
            CcspTraceInfo(("deviceMAC is %s\n", deviceMAC));
        }
        else
        {
            if(!Cosa_FindDestComp(getList, &dstComp, &dstPath) || !dstComp || !dstPath)
            {
                CcspHarvesterConsoleTrace(("RDK_LOG_ERROR, Can not find Dest Component \n"));
                sleep(10);
                continue;
            }            

            CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Before GPV %s %s\n", dstComp, dstPath));
            ret = CcspBaseIf_getParameterValues(bus_handle,
                        dstComp, dstPath,
                        getList1,
                        1, &val_size, &parameterval);
            CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, After GPV ret: %d\n",ret));
            if(ret == CCSP_SUCCESS)
            {
                CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, val_size : %d\n",val_size));
                for (cnt = 0; cnt < val_size; cnt++)
                {
                    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, parameterval[%d]->parameterName : %s\n",cnt,parameterval[cnt]->parameterName));
                    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, parameterval[%d]->parameterValue : %s\n",cnt,parameterval[cnt]->parameterValue));
                    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, parameterval[%d]->type :%d\n",cnt,parameterval[cnt]->type));
                
                }
                CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Calling macToLower to get deviceMacId\n"));
                AnscMacToLower(deviceMAC, parameterval[0]->parameterValue, sizeof(deviceMAC));
        
            }
            else
            {
                CcspHarvesterTrace(("RDK_LOG_ERROR, Failed to get values for %s ret: %d\n",getList,ret));
                CcspTraceError(("RDK_LOG_ERROR, Failed to get values for %s ret: %d\n",getList,ret));
	        	sleep(10);
            }
            /* CID: 54087 & 60662 Resource leak 
               Dealloc common for both success and failure case*/
            if(dstComp)
            {
               AnscFreeMemory(dstComp);
            }
            if(dstPath)
            {
               AnscFreeMemory(dstPath);
            }

         
            CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Before free_parameterValStruct_t...\n"));
            free_parameterValStruct_t(bus_handle, val_size, parameterval);
            CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, After free_parameterValStruct_t...\n"));    
        }
    }
        
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, Harvester %s EXIT\n", __FUNCTION__ ));

    return deviceMAC;
}

