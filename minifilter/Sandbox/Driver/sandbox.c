#include "precom.h"

UNICODE_STRING			g_SandboxPath;//\\device\\HarddiskVolume1\\sandbox\\ 
UNICODE_STRING			g_SandboxDosPath;//c:\\ 
extern PFLT_FILTER		gp_Filter;
UNICODE_STRING			g_ustrVolumeDeviceName;//\\device\\HarddiskVolume1   
PFLT_INSTANCE			g_SbVolInstance;


NTSTATUS
InitSb()
{

	RtlInitUnicodeString(&g_SandboxPath, L"\\device\\HarddiskVolume1\\sandbox\\");
	RtlInitUnicodeString(&g_SandboxDosPath, L"c:\\");
	RtlInitUnicodeString(&g_ustrVolumeDeviceName, L"\\device\\HarddiskVolume1");

	return STATUS_SUCCESS;
}


NTSTATUS sbPreCreateFile(
	IN OUT PFLT_CALLBACK_DATA Data,
	IN PCFLT_RELATED_OBJECTS FltObjects
	)
{

	NTSTATUS		ntStatus = STATUS_SUCCESS;
	ULONG			ulDisposition = 0;
	BOOLEAN 		bNeedFree		= FALSE;
	BOOLEAN			bDir  = FALSE;
	BOOLEAN			bIsRename		= FALSE;
	BOOLEAN			bIsHardLink   = TRUE;
	BOOLEAN			bCreateFile	= FALSE;
	PWCHAR			pFileName = NULL;
	PEPROCESS		pEprocess = PsGetCurrentProcess();
	PACCESS_STATE	accessState;
	PFILE_OBJECT	OutFileObject = NULL;
	PFLT_INSTANCE	pOutVolumeInstance = NULL;
	UNICODE_STRING	ustrDstFile = {0};
	UNICODE_STRING  ustrSrcFile = {0};
	UNICODE_STRING	ustrDeledName = {0};
	PUNICODE_STRING pInName = NULL;
	PUNICODE_STRING pOutName = NULL;
	BOOLEAN			bReparsed = FALSE;
	BOOLEAN			bReqInSandbox = FALSE; 
	ACCESS_MASK		AccessMask = 0;
	PFLT_FILE_NAME_INFORMATION		pNameInfo = NULL;

	Data->IoStatus.Status = STATUS_UNSUCCESSFUL;
	accessState = Data->Iopb->Parameters.Create.SecurityContext->AccessState;
	
	__try
	{
		if((ExGetPreviousMode() == KernelMode) ||
		   (KeGetCurrentIrql() > APC_LEVEL) ||
		   (pEprocess == NULL) ||
		   (pEprocess == g_pProcessObject))
		{

			return STATUS_SUCCESS;
		}
		if (!SbShouldBeSandBoxed(PsGetProcessId(pEprocess)))
		{
			return STATUS_SUCCESS;
		}
		
		if(g_SbVolInstance == NULL)
		{
			g_SbVolInstance = SbGetVolumeInstance(gp_Filter, &g_ustrVolumeDeviceName);	

			if(g_SbVolInstance == NULL)
			{

				ntStatus = STATUS_SUCCESS;
				__leave;
			}
		}

		if(FltObjects->FileObject->Flags & FO_VOLUME_OPEN)
		{
			ntStatus = STATUS_SUCCESS;
			__leave;
		}

		bIsRename = (AccessMask == ( SYNCHRONIZE| FILE_READ_ATTRIBUTES| DELETE));
		bIsHardLink = (AccessMask == (SYNCHRONIZE | FILE_WRITE_DATA));
		AccessMask = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;


		if(!bIsRename && !bIsHardLink)
		{
			ntStatus = FltGetFileNameInformation(Data,
											FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
											&pNameInfo);

			if(NT_SUCCESS(ntStatus))
			{
				FltParseFileNameInformation(pNameInfo);
		    }
		}
		
		if ( bIsRename || bIsHardLink || !NT_SUCCESS(ntStatus ))
		{
			ntStatus = SbGetFileNameInformation(FltObjects->Volume,
												FltObjects->Instance,
												FltObjects->FileObject,
												FALSE,
												&pNameInfo);
			if (NT_SUCCESS(ntStatus))
			{
				bNeedFree = TRUE;
			}
			else
			{
				Data->IoStatus.Status = ntStatus;
				Data->IoStatus.Information = 0;
				__leave;
			}
		}

		if(!RtlCompareUnicodeString(&pNameInfo->Name, &pNameInfo->Volume, TRUE))//卷操作，放过
		{
			ntStatus = STATUS_SUCCESS;
			__leave;
		}
	

		if(pNameInfo->Name.Length >= sizeof(WCHAR)*DEL_LENGTH &&
			!_wcsnicmp(pNameInfo->Name.Buffer+pNameInfo->Name.Length/sizeof(WCHAR)-DEL_LENGTH,  //含有删除标志，返回失败
			DEL_MARK, DEL_LENGTH))
		{
			Data->IoStatus.Status = STATUS_OBJECT_NAME_NOT_FOUND;
			Data->IoStatus.Information = 0;
			ntStatus = STATUS_OBJECT_NAME_NOT_FOUND;
			__leave;
		}
		
		if(!RtlPrefixUnicodeString(&g_SandboxPath, &pNameInfo->Name, TRUE)) //来自外面的请求
		{
			ntStatus = SbConvertToSbName(&g_SandboxPath, &pNameInfo->Name, &ustrDstFile, NULL);//转换为内部请求
			if(!NT_SUCCESS(ntStatus))
			{
				Data->IoStatus.Status = ntStatus;
				Data->IoStatus.Information = 0;	
				__leave;
			}

			pInName  = &ustrDstFile;
			pOutName = &pNameInfo->Name;
			pOutVolumeInstance = FltObjects->Instance;
		}
		else //来自内部请求，转化一下，获得外部路径
		{
			UNICODE_STRING ustrVolName = {0};

			ustrVolName.Buffer = (PWCHAR)MyNew(BYTE, sizeof(WCHAR)*MAX_PATH);
			
			if(ustrVolName.Buffer == NULL)
			{
				ntStatus = STATUS_INSUFFICIENT_RESOURCES;
				Data->IoStatus.Status = ntStatus;
				Data->IoStatus.Information = 0;
				__leave;
			}

			ustrVolName.MaximumLength = sizeof(WCHAR)*MAX_PATH;

			ntStatus = SbConvertInSbNameToOutName(gp_Filter,
				&pNameInfo->Name, 
				&g_SandboxPath, 
				&ustrSrcFile, 
				&ustrVolName);
			if(!NT_SUCCESS(ntStatus))
			{
				MyDelete(ustrVolName.Buffer);
				Data->IoStatus.Status = ntStatus;
				Data->IoStatus.Information = 0;
				__leave;
			}

			ustrDstFile.Buffer = MyNew(WCHAR, pNameInfo->Name.Length/sizeof(WCHAR)); 
			if(ustrDstFile.Buffer == NULL)
			{
				MyDelete(ustrVolName.Buffer);
				ntStatus = STATUS_INSUFFICIENT_RESOURCES;
				Data->IoStatus.Status = ntStatus;
				Data->IoStatus.Information = 0;
				__leave;
			}

			ustrDstFile.Length = 0;
			ustrDstFile.MaximumLength = pNameInfo->Name.Length;

			RtlCopyUnicodeString(&ustrDstFile, &pNameInfo->Name);
			pInName = &ustrDstFile;
			pOutName = &ustrSrcFile;
			pOutVolumeInstance = SbGetVolumeInstance(gp_Filter, &ustrVolName);
			MyDelete(ustrVolName.Buffer);
			if (pOutVolumeInstance == NULL)
			{
				ntStatus = STATUS_UNSUCCESSFUL;
				Data->IoStatus.Status = ntStatus;
				Data->IoStatus.Information = 0;
				__leave;
			}
			bReqInSandbox = TRUE;
		}		

		ustrDeledName.MaximumLength = pInName->Length + DEL_LENGTH*sizeof(WCHAR);
		ustrDeledName.Buffer = MyNew(WCHAR, ustrDeledName.MaximumLength/sizeof(WCHAR));
		if(ustrDeledName.Buffer == NULL)
		{
			ntStatus = STATUS_INSUFFICIENT_RESOURCES;
			Data->IoStatus.Status = ntStatus;
			Data->IoStatus.Information = 0;
			__leave;
		}

		ulDisposition = (Data->Iopb->Parameters.Create.Options >> 24) & 0x000000ff;
		bCreateFile = (BOOLEAN)((ulDisposition == FILE_CREATE) ||
	                                 (ulDisposition == FILE_OPEN_IF) ||
	                                 (ulDisposition == FILE_OVERWRITE_IF) ||
	                                 (ulDisposition == FILE_SUPERSEDE));
		
		RtlCopyUnicodeString(&ustrDeledName, pInName);
		RtlAppendUnicodeToString(&ustrDeledName, DEL_MARK);

		if(SbFileExist(gp_Filter, g_SbVolInstance, &ustrDeledName))//内部存在该文件的删除标志
		{
			if(bCreateFile ||SbOperWillModifyFile(AccessMask)) //创建或者要改变该文件
			{
				if(!SbFileExist(gp_Filter,g_SbVolInstance, pInName)) //内部不存在该文件
				{

					
					ntStatus = SbPrepareSandboxPath(
								gp_Filter,
								g_SbVolInstance,
								&g_SandboxPath,
								pInName,
								AccessMask);
					
					if(! NT_SUCCESS(ntStatus))
					{
						Data->IoStatus.Status = ntStatus;
						Data->IoStatus.Information = 0;
						
						__leave;
					}
					if (! bReqInSandbox)
					{
						ntStatus = SbRedirectFile(Data,
											FltObjects,
											pInName);//来自外面请求，重定向创建该文件
						if(NT_SUCCESS(ntStatus))
						{
							ntStatus = STATUS_SB_TRY_REPARSE;
							__leave;
						}
					}
					else
					{
						if(!SBDeleteOneFile(g_SbVolInstance, gp_Filter, NULL, &ustrDeledName)) //来自内部，删除该标志
						{
							ntStatus = STATUS_UNSUCCESSFUL;
							Data->IoStatus.Status = ntStatus;
							Data->IoStatus.Information = 0;
							__leave;
						}
						
						ntStatus = STATUS_SUCCESS; //让文件系统执行
						__leave;
					}
				}	
			}
			else //表明访问了一个打了删除标志的文件，而且不是创建或者修改
			{

				Data->IoStatus.Status = STATUS_OBJECT_NAME_NOT_FOUND;
				Data->IoStatus.Information = 0;
				ntStatus = STATUS_OBJECT_NAME_NOT_FOUND;
				__leave;
			}
		}
		else //里面没有删除标志
		{
			if(bReqInSandbox) //来自于内部请求
			{
				if(!SbFileExist(FltObjects->Filter, pOutVolumeInstance, pOutName) )//外面不存在，直接交给文件系统创建
				{
					ntStatus = STATUS_SUCCESS;
					__leave;
				}
			}
		}
		//里面文件存在	
		if(SbFileExist(gp_Filter, g_SbVolInstance, pInName) )
		{
			if (bReqInSandbox)//来自里面的请求，直接交给文件系统
			{
				ntStatus = STATUS_SUCCESS;
				__leave;
			}
			ntStatus = SbRedirectFile(Data,
								FltObjects,
								pInName);//来自外面请求，重定向
		
			if(NT_SUCCESS(ntStatus))
			{
				ntStatus = STATUS_SB_TRY_REPARSE;
			}
			else
			{
				Data->IoStatus.Status = ntStatus;
				Data->IoStatus.Information = 0;
			}

		
			__leave;
		}
		//里面文件不存在，且不需要修改和创建该文件
		if(!bCreateFile && !SbOperWillModifyFile(AccessMask))
		{
			if (bReqInSandbox)//来自里面的请求
			{
				ntStatus = SbRedirectFile(Data,
									FltObjects,
									pOutName);//重定向到外面
				
				if(NT_SUCCESS(ntStatus))
				{
					ntStatus = STATUS_SB_TRY_REPARSE;
				}
				else
				{
					Data->IoStatus.Status = ntStatus;
					Data->IoStatus.Information = 0;
				}
				
				__leave;
			}
			ntStatus = STATUS_SUCCESS;
			__leave;
		}
		//里面文件不存在，需要修改和创建该文件
		ntStatus = SbPrepareSandboxPath(
								gp_Filter,
								g_SbVolInstance,
								&g_SandboxPath,
								pInName,
								Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess);
					
		if(! NT_SUCCESS(ntStatus))
		{
		
			Data->IoStatus.Status = ntStatus;
			Data->IoStatus.Information = 0;
		
			__leave;
		}
		
		if(bReqInSandbox || SbFileExist( FltObjects->Filter, pOutVolumeInstance, pOutName) )
		{
			//如果是来自内部请求，并且外部文件存在，则拷贝进来
			ntStatus = SbIsDirectory(NULL, pOutName, FltObjects->Filter, pOutVolumeInstance, &bDir);
			if(!NT_SUCCESS(ntStatus))
			{
				Data->IoStatus.Status = ntStatus;
				Data->IoStatus.Information = 0; 
				__leave;
			}
			
			ntStatus = SbCopyFile(gp_Filter,
								pOutVolumeInstance,
								NULL,
								pOutName,
								g_SbVolInstance,
								pInName,
								bDir);
			if(!NT_SUCCESS(ntStatus))
			{
				if(ntStatus != STATUS_SB_DIR_CREATED)
				{
					Data->IoStatus.Status = ntStatus;
					Data->IoStatus.Information = 0;
					__leave;
				}
			}
			if(bReqInSandbox)
			{
				ntStatus = STATUS_SUCCESS;
				__leave;
			}
			
		}

		//重定向到里面
		ntStatus = SbRedirectFile(Data,
								FltObjects,
								pInName);
	
		if(NT_SUCCESS(ntStatus))
		{
			ntStatus = STATUS_SB_TRY_REPARSE;	
		}
		else
		{
			Data->IoStatus.Status = ntStatus;
			Data->IoStatus.Information = 0;
		}
			

	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
	}

	
	if(pNameInfo != NULL)
	{
		if(bNeedFree)
			MyDelete(pNameInfo);
		else
			FltReleaseFileNameInformation(pNameInfo);
	}

	if(ustrDeledName.Buffer != NULL)
		MyDelete(ustrDeledName.Buffer);

	if(ntStatus == STATUS_SB_TRY_REPARSE)
	{
		Data->IoStatus.Status = STATUS_REPARSE;
		Data->IoStatus.Information = 0;
	}

	if(ustrDstFile.Buffer != NULL && ntStatus != STATUS_SB_TRY_REPARSE)
	{
		ExFreePool(ustrDstFile.Buffer);
		ustrDstFile.Buffer = NULL;
	}

	if(OutFileObject)
		ObDereferenceObject(OutFileObject);

	return ntStatus;
}



NTSTATUS
sbPostCreateFile(
	IN OUT PFLT_CALLBACK_DATA Data, 
	IN PCFLT_RELATED_OBJECTS FltObjects
	)
{
	NTSTATUS						ntStatus = STATUS_SUCCESS;
	ACCESS_MASK						AccessMask;
	BOOLEAN							bIsRename = FALSE;
	BOOLEAN							bIsHardLink = FALSE;
	BOOLEAN							bNeedFree  = FALSE;
	PFLT_FILE_NAME_INFORMATION		pNameInfo = NULL;
	PFILE_STREAMHANDLE_CONTEXT		pStreamHandleContext = NULL;
	UNICODE_STRING					ustrDstFile = {0};
	UNICODE_STRING					ustrSrcFile = {0};
	UNICODE_STRING					DeledName = {0};
	PUNICODE_STRING					pInName = NULL;
	PUNICODE_STRING					pOutName = NULL;
	PWCHAR							pFileName = NULL;
	PFLT_INSTANCE 					pOutInstance = NULL;
	BOOLEAN							bFileExistsOut = FALSE;
	BOOLEAN							bFileExistsIn = FALSE;
	UNICODE_STRING					ustrParentPath = {0};
	PEPROCESS						pEprocess = PsGetCurrentProcess();
	
	__try
	{
		if((ExGetPreviousMode() == KernelMode) ||
			(KeGetCurrentIrql() > APC_LEVEL)||
			(pEprocess == NULL) ||
		   (pEprocess == g_pProcessObject)
		   )
		{

			return STATUS_SUCCESS;
		}

		if(((!NT_SUCCESS(Data->IoStatus.Status) || 
			 Data->IoStatus.Status == STATUS_REPARSE)) && 
			(Data->IoStatus.Status  != STATUS_OBJECT_PATH_NOT_FOUND))
		{
			return STATUS_SUCCESS;
		}
			

		if(Data->IoStatus.Status == STATUS_OBJECT_PATH_NOT_FOUND)
		{

	
			ntStatus = SbGetFileNameInformation(FltObjects->Volume,
												FltObjects->Instance,
												FltObjects->FileObject,
												FALSE,
												&pNameInfo);
			if (NT_SUCCESS(ntStatus))
			{
				bNeedFree = TRUE;
			}
			else
			{
				ntStatus = STATUS_SUCCESS;
				__leave;
			}
		
			if(!RtlPrefixUnicodeString(&g_SandboxPath, &pNameInfo->Name, TRUE))
			{
				ntStatus = SbConvertToSbName(&g_SandboxPath, &pNameInfo->Name, &ustrDstFile, NULL);
				if(!NT_SUCCESS(ntStatus))
				{
					Data->IoStatus.Status = ntStatus;
					Data->IoStatus.Information = 0;	
					__leave;
				}

				pInName  = &ustrDstFile;
				pOutName = &pNameInfo->Name;
				pOutInstance = FltObjects->Instance;
			}
			else
			{
				UNICODE_STRING ustrVolName = {0};
				ustrVolName.Buffer = (PWCHAR)MyNew(BYTE, sizeof(WCHAR)*MAX_PATH);
				
				if(ustrVolName.Buffer == NULL)
				{
					ntStatus = STATUS_INSUFFICIENT_RESOURCES;
					Data->IoStatus.Status = ntStatus;
					Data->IoStatus.Information = 0;
					__leave;
				}

				ustrVolName.MaximumLength = sizeof(WCHAR)*MAX_PATH;

				ntStatus = SbConvertInSbNameToOutName(gp_Filter, &pNameInfo->Name, &g_SandboxPath, &ustrSrcFile, &ustrVolName);
				if(!NT_SUCCESS(ntStatus))
				{
					MyDelete(ustrVolName.Buffer);
					Data->IoStatus.Status = ntStatus;
					Data->IoStatus.Information = 0;
					__leave;
				}

				ustrDstFile.Buffer = MyNew(WCHAR, pNameInfo->Name.Length/sizeof(WCHAR)); 
				if(ustrDstFile.Buffer == NULL)
				{
					MyDelete(ustrVolName.Buffer);
					ntStatus = STATUS_INSUFFICIENT_RESOURCES;
					Data->IoStatus.Status = ntStatus;
					Data->IoStatus.Information = 0;
					__leave;
				}

				ustrDstFile.Length = 0;
				ustrDstFile.MaximumLength = pNameInfo->Name.Length;

				RtlCopyUnicodeString(&ustrDstFile, &pNameInfo->Name);
				pInName = &ustrDstFile;
				pOutName = &ustrSrcFile;
				pOutInstance = SbGetVolumeInstance(gp_Filter, &ustrVolName);
				MyDelete(ustrVolName.Buffer);
				if (pOutInstance == NULL)
				{
					ntStatus = STATUS_UNSUCCESSFUL;
					Data->IoStatus.Status = ntStatus;
					Data->IoStatus.Information = 0;
					__leave;
				}
			}
			ntStatus = SbGetParentPath(pOutName, &ustrParentPath, FALSE);
			if (NT_SUCCESS(ntStatus))
				bFileExistsOut = SbFileExist(gp_Filter , pOutInstance, &ustrParentPath);
			ntStatus = SbGetParentPath(pInName, &ustrParentPath, TRUE);
			if (NT_SUCCESS(ntStatus))
				bFileExistsIn = SbFileExist(gp_Filter, g_SbVolInstance, &ustrParentPath);
			if(!bFileExistsOut && bFileExistsIn &&
				Data->IoStatus.Status == STATUS_OBJECT_PATH_NOT_FOUND)
			{
				Data->IoStatus.Status = STATUS_OBJECT_NAME_NOT_FOUND;
				ntStatus = STATUS_SUCCESS;
				__leave;
			}
			
			__leave;
		}
		
		ntStatus = FltGetStreamHandleContext(FltObjects->Instance,
											 FltObjects->FileObject,
											 &pStreamHandleContext);
		if (  ntStatus == STATUS_NOT_FOUND)
		{
			ntStatus = FltAllocateContext(gp_Filter,
										  FLT_STREAMHANDLE_CONTEXT,
										  sizeof(FILE_STREAMHANDLE_CONTEXT),
										  PagedPool,
										  &pStreamHandleContext);
			if(!NT_SUCCESS(ntStatus))
			{
				ntStatus =  STATUS_SUCCESS;
				__leave;
			}
		
			pStreamHandleContext->outSideSbFileObj = NULL;
			RtlZeroMemory(pStreamHandleContext->m_Name, MAX_PATH);
			pStreamHandleContext->m_FileName[0] = 0;
		}
		else if(!NT_SUCCESS( ntStatus))
		{
			ntStatus = STATUS_SUCCESS;
			__leave;
		}
		
		AccessMask = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
		bIsRename = (AccessMask == ( SYNCHRONIZE| FILE_READ_ATTRIBUTES| DELETE));
		bIsHardLink = (AccessMask == (SYNCHRONIZE | FILE_WRITE_DATA));
		
		if(!bIsRename && !bIsHardLink)
		{
			ntStatus = FltGetFileNameInformation(Data,
											FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
											&pNameInfo);
		
			if(NT_SUCCESS(ntStatus))
				FltParseFileNameInformation(pNameInfo);
		}
		
		if ( bIsRename || bIsHardLink || !NT_SUCCESS(ntStatus ))
		{
			ntStatus = SbGetFileNameInformation(FltObjects->Volume,
												FltObjects->Instance,
												FltObjects->FileObject,
												FALSE,
												&pNameInfo);
			if (NT_SUCCESS(ntStatus))
			{
				bNeedFree = TRUE;
			}
			else
			{
				ntStatus = STATUS_SUCCESS;
				__leave;
			}
		}
		if (pNameInfo->Name.Length >= MAX_PATH * sizeof(WCHAR) )
		{
			ntStatus = STATUS_SUCCESS;
			__leave;
		}
		RtlCopyMemory(pStreamHandleContext->m_FileName, pNameInfo->Name.Buffer, pNameInfo->Name.Length);
		pStreamHandleContext->m_FileName[pNameInfo->Name.Length / sizeof(WCHAR)] = 0;
		FltSetStreamHandleContext(FltObjects->Instance,
								FltObjects->FileObject,
								FLT_SET_CONTEXT_REPLACE_IF_EXISTS,
								pStreamHandleContext, 
								NULL);
		ntStatus = STATUS_SUCCESS;
		
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{

	}
	

	if(pNameInfo != NULL)
	{
		if(bNeedFree)
			MyDelete(pNameInfo);
		else
			FltReleaseFileNameInformation(pNameInfo);
	}

	if (pStreamHandleContext)
		FltReleaseContext(pStreamHandleContext);
	
	return ntStatus;
	
}

NTSTATUS
SbSetInfoForDelete(
	IN PFLT_CALLBACK_DATA		Data,
	IN PCFLT_RELATED_OBJECTS 	FltObjects,
	IN PFLT_FILE_NAME_INFORMATION	pNameInfo,
	IN PUNICODE_STRING			ustrSandboxPath
	)
{
	NTSTATUS						ntStatus = STATUS_SUCCESS;
	PFILE_DISPOSITION_INFORMATION 	pDispositionInfo;
	UNICODE_STRING					ustrDstFileName = {0, 0, 0};
	UNICODE_STRING					MarkDelFile = {0, 0, 0};
	UNICODE_STRING					realName = {0, 0, 0};
	UNICODE_STRING					volName = {0, 0, 0};
	PUNICODE_STRING					pDelFileName = NULL;
	BOOLEAN							bContinueFS = FALSE;
	PFILE_STREAMHANDLE_CONTEXT		pStreamHandleContext = NULL;			
	BOOLEAN							bCreateDel = FALSE;
	BOOLEAN							bDirectory = FALSE;
	PFLT_FILTER						pFilter = NULL;
	PFLT_INSTANCE					pInstance = NULL;

	pDispositionInfo = (PFILE_DISPOSITION_INFORMATION)Data->Iopb->Parameters.SetFileInformation.InfoBuffer;

	__try
	{
		ntStatus = FltGetStreamHandleContext(FltObjects->Instance,
											 FltObjects->FileObject,
											 &pStreamHandleContext);
		if(STATUS_NOT_SUPPORTED == ntStatus)
			__leave;

		if(ntStatus == STATUS_NOT_FOUND)
		{
			ntStatus = FltAllocateContext(gp_Filter,
										  FLT_STREAMHANDLE_CONTEXT,
										  sizeof(FILE_STREAMHANDLE_CONTEXT),
										  PagedPool,
										  &pStreamHandleContext);
			if(!NT_SUCCESS(ntStatus))
				__leave;

			pStreamHandleContext->outSideSbFileObj = NULL;
			pStreamHandleContext->m_FileName[0] = 0;
			RtlZeroMemory(pStreamHandleContext->m_Name, MAX_PATH);

			FltSetStreamHandleContext(FltObjects->Instance,
									FltObjects->FileObject,
									FLT_SET_CONTEXT_KEEP_IF_EXISTS,
									pStreamHandleContext, NULL);
		}
		
		{


			if( !RtlPrefixUnicodeString(ustrSandboxPath, &pNameInfo->Name, TRUE)) //来自外面
			{
				SbConvertToSbName(ustrSandboxPath, &pNameInfo->Name, &ustrDstFileName, NULL);
				if(! NT_SUCCESS(ntStatus))
					__leave;

				pDelFileName = &ustrDstFileName;
				bCreateDel = TRUE;

				pFilter = gp_Filter;
				pInstance = g_SbVolInstance;

				bContinueFS = TRUE;
			}

			if(RtlPrefixUnicodeString(ustrSandboxPath, &pNameInfo->Name, TRUE)) //来自里面
			{
				volName.Buffer = MyNew(WCHAR, MAX_PATH);
				if(volName.Buffer == NULL )
				{
					ntStatus = STATUS_INSUFFICIENT_RESOURCES;
					__leave;
				}

				volName.Length  = 0;
				volName.MaximumLength = MAX_PATH * sizeof(WCHAR);

				SbConvertInSbNameToOutName(FltObjects->Filter, &pNameInfo->Name, ustrSandboxPath, &realName, &volName);
				if(SbFileExist(gp_Filter, FltObjects->Instance, &pNameInfo->Name)) //里面存在
					bContinueFS = TRUE;
				if(SbFileExist(gp_Filter, SbGetVolumeInstance(gp_Filter, &volName), &realName)) //外面也存在
				{
					bCreateDel = TRUE;

					pDelFileName = &pNameInfo->Name;

					pFilter = FltObjects->Filter;
					pInstance = FltObjects->Instance;
				}
			}

			if(bCreateDel && (pDispositionInfo->DeleteFile))
			{
				ULONG CreateOptions = FILE_SYNCHRONOUS_IO_NONALERT;
				pStreamHandleContext->m_bDelete = pDispositionInfo->DeleteFile;
				SbIsDirectory(FltObjects->FileObject, pDelFileName, pFilter, pInstance, &bDirectory);

				MarkDelFile.MaximumLength = pDelFileName->Length + sizeof(WCHAR)*DEL_LENGTH;
				MarkDelFile.Buffer = MyNew(WCHAR, MarkDelFile.MaximumLength);
				if(MarkDelFile.Buffer == NULL)
				{
					ntStatus = STATUS_INSUFFICIENT_RESOURCES;
					__leave;
				}
				

				RtlCopyUnicodeString(&MarkDelFile, pDelFileName);
				RtlAppendUnicodeToString(&MarkDelFile, DEL_MARK);

				ntStatus = SbPrepareSandboxPath(
											gp_Filter,
											g_SbVolInstance,
											ustrSandboxPath,
											&MarkDelFile,
											0);
								
				if(! NT_SUCCESS(ntStatus))
				{
					if(ntStatus == STATUS_ACCESS_DENIED)
					{
						Data->IoStatus.Status = STATUS_ACCESS_DENIED;
						Data->IoStatus.Information = 0;
					}
					__leave;
				}

				if(!SbCreateOneFile(gp_Filter, g_SbVolInstance, NULL, &MarkDelFile,
					FALSE, 0, 0, bDirectory))
				{
					ntStatus = STATUS_UNSUCCESSFUL;
					__leave;
				}
					
				
				if(bContinueFS)
				{
					ntStatus = STATUS_SUCCESS;
				}
				else
				{
					Data->IoStatus.Status = STATUS_SUCCESS;
					Data->IoStatus.Information = 0;
					ntStatus = STATUS_UNSUCCESSFUL;
				}
			}

			if((pStreamHandleContext->m_bDelete) && (!pDispositionInfo->DeleteFile))
			{
				pStreamHandleContext->m_bDelete = FALSE;

				MarkDelFile.MaximumLength = pDelFileName->Length + sizeof(WCHAR)*DEL_LENGTH;
				MarkDelFile.Buffer = MyNew(WCHAR, MarkDelFile.MaximumLength);
				if(MarkDelFile.Buffer == NULL)
				{
					ntStatus = STATUS_INSUFFICIENT_RESOURCES;
					__leave;
				}

				RtlCopyUnicodeString(&MarkDelFile, pDelFileName);
				RtlAppendUnicodeToString(&MarkDelFile, DEL_MARK);

				SBDeleteOneFile(g_SbVolInstance, gp_Filter, NULL, &MarkDelFile);
			}
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		ntStatus = GetExceptionCode();
	}

	if(pStreamHandleContext)
		FltReleaseContext(pStreamHandleContext);
	if( MarkDelFile.Buffer)
		MyDelete(MarkDelFile.Buffer);
	if(realName.Buffer)
		MyDelete(realName.Buffer);
	if(volName.Buffer)
		MyDelete(volName.Buffer);
	if(ustrDstFileName.Buffer)
		MyDelete(ustrDstFileName.Buffer);
	
	return ntStatus;
}

NTSTATUS
sbPreSetInformationFile(
	IN OUT PFLT_CALLBACK_DATA Data, 
	IN PCFLT_RELATED_OBJECTS FltObjects
	)
{
	NTSTATUS						ntStatus		= STATUS_SUCCESS;
	ULONG							uQueryType		= 0;
	BOOLEAN							bNeedFree		= FALSE;	
	PFILE_OBJECT 					pFileObject		= NULL;
	HANDLE							hFile			= NULL;
	PFLT_FILE_NAME_INFORMATION		pNameInfo		= NULL;
	PEPROCESS						pEprocess		= PsGetCurrentProcess();


	uQueryType = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
	__try 
	{

		if( (KeGetCurrentIrql() > APC_LEVEL) ||
			(ExGetPreviousMode() == KernelMode)||
			(pEprocess == NULL) ||
		   (pEprocess == g_pProcessObject)
		  )
		{

			return STATUS_SUCCESS;
		}
		

		if(uQueryType != FileRenameInformation && 
			uQueryType != FileDispositionInformation)
		{
			return STATUS_SUCCESS;
		}
		
		ntStatus = FltGetFileNameInformation(Data,
											 FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
											 &pNameInfo);
		if(!NT_SUCCESS(ntStatus))
		{
			ntStatus = SbGetFileNameInformation(FltObjects->Volume,
												FltObjects->Instance,
												FltObjects->FileObject,
												TRUE,
												&pNameInfo);
			if(!NT_SUCCESS(ntStatus))
			{
				ntStatus = STATUS_SUCCESS;
				__leave;
			}
			
			bNeedFree = TRUE;
		}

		if(Data->Iopb->Parameters.SetFileInformation.InfoBuffer)
		{

			switch(uQueryType)
			{
				case FileRenameInformation:
					break;
				case FileDispositionInformation:
					ntStatus = SbSetInfoForDelete(Data, FltObjects, pNameInfo, &g_SandboxPath);
					Data->IoStatus.Status = ntStatus;
					Data->IoStatus.Information = 0;
					
					if(!NT_SUCCESS(ntStatus))
						ntStatus = STATUS_UNSUCCESSFUL;
					break;
				case FileLinkInformation:
					break;
			}
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		ntStatus = GetExceptionCode();
	}
	
	if(pNameInfo)
	{
		if(bNeedFree)
			MyDelete(pNameInfo);
		else
			FltReleaseFileNameInformation(pNameInfo);
	}
		
	return ntStatus;

}



NTSTATUS
sbPostSetInformationFile(
	IN OUT PFLT_CALLBACK_DATA Data, 
	IN PCFLT_RELATED_OBJECTS FltObjects
	)
{
	PFLT_FILE_NAME_INFORMATION		pNameInfo		= NULL;
	BOOLEAN							bNeedFree		= FALSE;
	BOOLEAN							bDirectory		= FALSE;
	NTSTATUS						ntStatus		= STATUS_UNSUCCESSFUL;
	PEPROCESS						pEprocess		= PsGetCurrentProcess();
	
	__try 
	{

		if(KeGetCurrentIrql() > APC_LEVEL ||
			ExGetPreviousMode() == KernelMode||
			pEprocess == NULL ||
		    pEprocess == g_pProcessObject
		   )
		{


			return STATUS_SUCCESS;
		}
		

		ntStatus = FltGetFileNameInformation(Data,
											 FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
											 &pNameInfo);
		if(!NT_SUCCESS(ntStatus))
		{
			ntStatus = SbGetFileNameInformation(FltObjects->Volume,
												FltObjects->Instance,
												FltObjects->FileObject,
												TRUE,
												&pNameInfo);
			if(!NT_SUCCESS(ntStatus))
			{
				ntStatus = STATUS_SUCCESS;
				__leave;
			}
										
			bNeedFree = TRUE;
		}

		if( (Data->IoStatus.Status == STATUS_DIRECTORY_NOT_EMPTY) && 
			(RtlPrefixUnicodeString(&g_SandboxPath, &pNameInfo->Name, TRUE)))
		{
			ntStatus = SbIsDirectory(FltObjects->FileObject, &pNameInfo->Name, FltObjects->Filter,
				FltObjects->Instance, &bDirectory);

			if(NT_SUCCESS(ntStatus))
			{
				UNICODE_STRING 		QueryName = {0, 0, 0};
				UNICODE_STRING		FEName = {0, 0, 0};
				PVOID				pInSBBuffer = NULL;
				ULONG				bufferSize = 0;
			
				if(bDirectory)
				{
					RtlInitUnicodeString(&QueryName, L"*");
					ntStatus = SbTraverseDirectory(FltObjects->Instance,FltObjects->FileObject, &QueryName,
							FileBothDirectoryInformation, &pInSBBuffer, &bufferSize);

					if(NT_SUCCESS(ntStatus))
					{
						BOOLEAN bDeleted = FALSE;
						PBYTE 	pNode = (PBYTE)pInSBBuffer;
						BOOLEAN bLastNode = FALSE;
						ULONG	NameLength = 0;
						ULONG	CurPos = 0;
						ULONG 	ulNameOffset = FIELD_OFFSET(FILE_BOTH_DIR_INFORMATION, FileName);
						ULONG 	ulNameLengthOffset = FIELD_OFFSET(FILE_BOTH_DIR_INFORMATION, FileNameLength);

						while(CurPos < bufferSize)
						{
							if((*(pNode+ulNameOffset)=='.') && 
								((*(PULONG)(pNode+ulNameLengthOffset) == 2) || 
								(*(PULONG)(pNode+ulNameLengthOffset) == 4)))
							{
								CurPos += FI_GET_NEXT_ENTRY_OFFSET(pNode);
								pNode = FI_GET_NEXT_ENTRY(pNode);
								continue;
							}
							
							NameLength = *(PULONG)((PBYTE)pNode+ulNameLengthOffset)+pNameInfo->Name.Length + sizeof(WCHAR);
							FEName.Buffer = MyNew(WCHAR, NameLength);
							if(!FEName.Buffer)
							{
								ntStatus = STATUS_INSUFFICIENT_RESOURCES;
								__leave;
							}

							RtlCopyMemory(FEName.Buffer, pNameInfo->Name.Buffer, pNameInfo->Name.Length);
							RtlCopyMemory((PBYTE)FEName.Buffer+pNameInfo->Name.Length, L"\\", sizeof(WCHAR));
							RtlCopyMemory((PBYTE)FEName.Buffer+pNameInfo->Name.Length+sizeof(WCHAR), FI_GET_FILE_NAME(pNode, ulNameOffset), 
								FI_GET_FILE_NAME_LEN(pNode,ulNameLengthOffset));
							FEName.Length = FEName.MaximumLength = (USHORT)NameLength;

							bDeleted = SBDeleteOneFile(FltObjects->Instance, FltObjects->Filter, NULL, &FEName);

							if(bDeleted)
							{						
								if(0 == FI_GET_NEXT_ENTRY_OFFSET(pNode))
								{
									CurPos = bufferSize;
									goto doLeave;
								}
								
								CurPos += FI_GET_NEXT_ENTRY_OFFSET(pNode);
								pNode = FI_GET_NEXT_ENTRY(pNode);
								
							}
							else
							{
								CurPos = bufferSize;
							}
doLeave:
							if(NULL != FEName.Buffer)
							{
								MyDelete(FEName.Buffer);
								FEName.Buffer = NULL;
							}
						}

						if(SBDeleteOneFile(FltObjects->Instance, FltObjects->Filter,
							FltObjects->FileObject, NULL))
						{
							Data->IoStatus.Status = STATUS_SUCCESS;
							Data->IoStatus.Information = 0;
						}
					}
				}
			}
		}
		
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		ntStatus = GetExceptionCode();
	}

	
	if(pNameInfo)
	{
		if(bNeedFree)
			MyDelete(pNameInfo);
		else
			FltReleaseFileNameInformation(pNameInfo);
	}

	if(! NT_SUCCESS(ntStatus))
	{
		Data->IoStatus.Status = ntStatus;
		Data->IoStatus.Information = 0;
	}
	return ntStatus;
}