import idautils
s=0x540
e=0x3223c
def func_len(a):
	return a['len']
def get_func_len():
	print 'Please define start address s and end address e'
	funcs = Functions(start=s,end=e)
	l=[]
	oldi=0
	i = funcs.next()
	while i!=oldi:
		oldi = i
		try:
			j = funcs.next()
		except:
			break
        #name = GetFunctionName(i)
        #l.append({'start_addr':i,'len':j-i,'name':name})
        l.append({'start_addr':i,'len':j-i})
        i=j
	return l
l = get_func_len()
ll=sorted(l,key=func_len)
lll=list(filter(lambda x: x['len'] > 500, ll))
for _ in lll:
	print _
'''
{'start_addr': 453896L, 'name': '___OSKextGetDiagnostics', 'len': 508L}
{'start_addr': 189920L, 'name': '__KextManagerCreatePropertyValueArray', 'len': 510L}
{'start_addr': 339409L, 'name': '_IOHIDEventQueueCreateWithVM', 'len': 511L}
{'start_addr': 388715L, 'name': '___OSKextPersonalityBundleIdentifierApplierFunction', 'len': 517L}
{'start_addr': 48752L, 'name': '__validUPSShutdownSettings', 'len': 519L}
{'start_addr': 516811L, 'name': '_io_registry_entry_get_property_bytes', 'len': 520L}
{'start_addr': 291629L, 'name': '___IOHIDEventSystemClientInitReplyPort', 'len': 523L}
{'start_addr': 47362L, 'name': '_IOPMRequestSysWake', 'len': 528L}
{'start_addr': 482984L, 'name': '__io_hideventsystem_open', 'len': 528L}
{'start_addr': 524840L, 'name': '_io_registry_entry_get_property_recursively', 'len': 529L}
{'start_addr': 534399L, 'name': '_io_registry_entry_get_property_bin', 'len': 529L}
{'start_addr': 81604L, 'name': '__IOFBGetDisplayModeInformation', 'len': 532L}
{'start_addr': 238819L, 'name': '___IOHIDManagerDeviceAdded', 'len': 533L}
{'start_addr': 324982L, 'name': '___IOHIDServiceFree', 'len': 539L}
{'start_addr': 356033L, 'name': '_OSKextSetArchitecture', 'len': 540L}
{'start_addr': 173088L, 'name': '__ZN10ExportInfo14appendToStreamERNSt3__16vectorIhNS0_9allocatorIhEEEE', 'len': 541L}
{'start_addr': 530539L, 'name': '_io_service_add_interest_notification', 'len': 543L}
{'start_addr': 217257L, 'name': '___IOHIDElementLoadProperties', 'len': 544L}
{'start_addr': 298574L, 'name': '___IOHIDEventSystemClientQueueCallback', 'len': 546L}
{'start_addr': 70276L, 'name': '_IOFramebufferServerOpen', 'len': 548L}
{'start_addr': 203397L, 'name': '_IOPMCopyPowerHistoryDetailed', 'len': 548L}
{'start_addr': 385836L, 'name': '_OSKextGetExecutableURL', 'len': 549L}
{'start_addr': 202847L, 'name': '_IOPMCopyPowerHistory', 'len': 550L}
{'start_addr': 79023L, 'name': '_IOFBSetKernelDisplayConfig', 'len': 553L}
{'start_addr': 390731L, 'name': '_OSKextCopyResource', 'len': 553L}
{'start_addr': 531082L, 'name': '_io_service_add_notification_ool', 'len': 553L}
{'start_addr': 303073L, 'name': '__IOHIDEventSystemClientCopyEventForService', 'len': 555L}
{'start_addr': 313887L, 'name': '__IOHIDServiceSetPropertyForClient', 'len': 556L}
{'start_addr': 234662L, 'name': '___IOHIDManagerDeviceApplier', 'len': 560L}
{'start_addr': 45292L, 'name': '_IOPMSchedulePowerEvent', 'len': 561L}
{'start_addr': 359167L, 'name': '_OSKextCreate', 'len': 565L}
{'start_addr': 370087L, 'name': '___OSKextCheckURL', 'len': 574L}
{'start_addr': 460932L, 'name': '___OSKextGetSegmentInfoForOffset', 'len': 574L}
{'start_addr': 75297L, 'name': '_IOFBResetTransform', 'len': 575L}
{'start_addr': 88721L, 'name': '_IOPSAllocateBlitEngine', 'len': 576L}
{'start_addr': 170595L, 'name': '__ZNSt3__113__tree_removeIPNS_16__tree_node_baseIPvEEEEvT_S5_', 'len': 576L}
{'start_addr': 36109L, 'name': '_getHostPrefsPath', 'len': 577L}
{'start_addr': 300815L, 'name': '___IOHIDEventSystemClientCacheMatchingServices', 'len': 587L}
{'start_addr': 38352L, 'name': '_IOPMCopyPMPreferences', 'len': 588L}
{'start_addr': 529951L, 'name': '_io_service_add_notification', 'len': 588L}
{'start_addr': 492601L, 'name': '___createAsyncAssertion_block_invoke', 'len': 589L}
{'start_addr': 536114L, 'name': '_io_service_add_notification_bin', 'len': 590L}
{'start_addr': 403943L, 'name': '___OSKextLogDependencyGraphApplierFunction', 'len': 596L}
{'start_addr': 493324L, 'name': '___releaseAsyncAssertion_block_invoke', 'len': 610L}
{'start_addr': 379325L, 'name': '___OSKextSendKextRequest', 'len': 617L}
{'start_addr': 232174L, 'name': '___IOHIDDeviceCopyDebugDescription', 'len': 618L}
{'start_addr': 377185L, 'name': '___OSKextProcessLoadInfo', 'len': 618L}
{'start_addr': 146588L, 'name': '__ZN5kcgen8AdjustorI9Pointer32I12LittleEndianEE17adjustInstructionEhyy', 'len': 620L}
{'start_addr': 184250L, 'name': '__ZN5kcgen8AdjustorI9Pointer64I12LittleEndianEE17adjustInstructionEhyy', 'len': 622L}
{'start_addr': 384123L, 'name': '___OSKextAddDiagnostic', 'len': 626L}
{'start_addr': 222764L, 'name': '_macho_trim_linkedit', 'len': 631L}
{'start_addr': 269943L, 'name': '_IOHIDEventCreateWithBytes', 'len': 635L}
{'start_addr': 382970L, 'name': '_OSKextCopyExecutableForArchitecture', 'len': 635L}
{'start_addr': 287277L, 'name': '___IOHIDEventSystemAddServices', 'len': 638L}
{'start_addr': 313005L, 'name': '___IOHIDServiceCopyPropertyForClient', 'len': 641L}
{'start_addr': 216428L, 'name': '_IOHIDElementSetProperty', 'len': 642L}
{'start_addr': 474765L, 'name': '__IOHIDEventSystemConnectionFilterEvent', 'len': 645L}
{'start_addr': 103321L, 'name': '__IOFBInstallScaledResolution', 'len': 646L}
{'start_addr': 497975L, 'name': '_IOPMAssertionSetProperty', 'len': 648L}
{'start_addr': 295719L, 'name': '_IOHIDEventSystemClientCreateWithType', 'len': 649L}
{'start_addr': 342684L, 'name': '_OSKextVersionGetString', 'len': 662L}
{'start_addr': 104318L, 'name': '_IOCheckTimingWithDisplay', 'len': 664L}
{'start_addr': 380244L, 'name': '_OSKextCopyLoadListForKexts', 'len': 675L}
{'start_addr': 385160L, 'name': '___OSKextReadExecutable', 'len': 676L}
{'start_addr': 213052L, 'name': '_IOHIDSessionFilterCreate', 'len': 684L}
{'start_addr': 458000L, 'name': '___OSKextAddCompressedFileToMkext', 'len': 688L}
{'start_addr': 292200L, 'name': '___IOHIDEventSystemClientTerminationCallback', 'len': 690L}
{'start_addr': 451152L, 'name': '___OSKextReleaseContents', 'len': 696L}
{'start_addr': 374653L, 'name': '___OSKextCreateIdentifierCacheDict', 'len': 703L}
{'start_addr': 297333L, 'name': '___IOHIDEventSystemClientSetupAsyncSupport', 'len': 707L}
{'start_addr': 315691L, 'name': '__IOHIDServiceOpen', 'len': 707L}
{'start_addr': 92240L, 'name': '_IOFBInterestCallback', 'len': 723L}
{'start_addr': 322109L, 'name': '__IOHIDServiceCopyRecordForClient', 'len': 723L}
{'start_addr': 335628L, 'name': '_____IOHIDSessionScheduleAsync_block_invoke', 'len': 724L}
{'start_addr': 458844L, 'name': '___OSKextGetSegmentInfo', 'len': 725L}
{'start_addr': 237251L, 'name': '___IOHIDPropertyLoadDictionaryFromKey', 'len': 743L}
{'start_addr': 375669L, 'name': '_OSKextCreateWithIdentifier', 'len': 748L}
{'start_addr': 148932L, 'name': '__ZN4TrieI10ExportInfoE17processExportNodeEPKhS3_S3_PciRNSt3__16vectorINS1_15EntryWithOffsetENS5_9allocatorIS7_EEEE', 'len': 752L}
{'start_addr': 69367L, 'name': '_IOFramebufferServerStart', 'len': 759L}
{'start_addr': 78258L, 'name': '_DetailedTimingsEqual', 'len': 765L}
{'start_addr': 219536L, 'name': '_macho_find_symbol', 'len': 765L}
{'start_addr': 37428L, 'name': '_setPreferencesForSrc', 'len': 770L}
{'start_addr': 147208L, 'name': '__ZN5kcgen8AdjustorI9Pointer32I12LittleEndianEE17adjustExportsTrieERNSt3__16vectorIhNS5_9allocatorIhEEEE', 'len': 770L}
{'start_addr': 184872L, 'name': '__ZN5kcgen8AdjustorI9Pointer64I12LittleEndianEE17adjustExportsTrieERNSt3__16vectorIhNS5_9allocatorIhEEEE', 'len': 770L}
{'start_addr': 412750L, 'name': '_OSKextSendKextPersonalitiesToKernel', 'len': 770L}
{'start_addr': 466902L, 'name': '_IOHIDServiceFilterCreate', 'len': 781L}
{'start_addr': 490472L, 'name': '_processCheckAssertionsMsg', 'len': 795L}
{'start_addr': 392198L, 'name': '__excludeThisVersion', 'len': 796L}
{'start_addr': 133120L, 'name': '__ZN5kcgen26adjustKextSegmentLocationsE8ArchPairPhRKNSt3__16vectorIyNS2_9allocatorIyEEEES8_S8_S8_RNS3_IPvNS4_IS9_EEEE', 'len': 806L}
{'start_addr': 373841L, 'name': '__OSKextWriteIdentifierCacheForKextsInDirectory', 'len': 812L}
{'start_addr': 42870L, 'name': '_IOPMFeatureIsAvailableWithSupportedTable', 'len': 819L}
{'start_addr': 407878L, 'name': '___OSKextCopyStrippedExecutable', 'len': 828L}
{'start_addr': 270888L, 'name': '_IOHIDEventGetPolicy', 'len': 841L}
{'start_addr': 452213L, 'name': '___OSKextRecordKextInIdentifierDict', 'len': 841L}
{'start_addr': 223560L, 'name': '_IOHIDDeviceCreate', 'len': 846L}
{'start_addr': 174262L, 'name': '__ZN5kcgen8AdjustorI9Pointer64I12LittleEndianEEC2EPvP12macho_headerIS3_ERKNSt3__16vectorIyNS9_9allocatorIyEEEESF_SF_SF_', 'len': 848L}
{'start_addr': 411121L, 'name': '___OSKextCheckLoaded', 'len': 848L}
{'start_addr': 508231L, 'name': '___IOHIDUserDeviceQueueCallback', 'len': 849L}
{'start_addr': 135848L, 'name': '__ZN5kcgen8AdjustorI9Pointer32I12LittleEndianEEC2EPvP12macho_headerIS3_ERKNSt3__16vectorIyNS9_9allocatorIyEEEESF_SF_SF_', 'len': 852L}
{'start_addr': 420147L, 'name': '___OSKextAuthenticateURLRecursively', 'len': 855L}
{'start_addr': 323529L, 'name': '__IOHIDServiceCopyEventLog', 'len': 856L}
{'start_addr': 43689L, 'name': '_IOPMRemoveIrrelevantProperties', 'len': 858L}
{'start_addr': 321240L, 'name': '__IOHIDServiceCopyDebugDescriptionForClient', 'len': 869L}
{'start_addr': 391284L, 'name': '_OSKextIsInExcludeList', 'len': 870L}
{'start_addr': 527874L, 'name': '_io_connect_method', 'len': 872L}
{'start_addr': 473181L, 'name': '_IOHIDEventSystemConnectionDispatchEvent', 'len': 887L}
{'start_addr': 485947L, 'name': '__io_hideventsystem_set_properties_for_service', 'len': 887L}
{'start_addr': 531878L, 'name': '_io_connect_method_var_output', 'len': 887L}
{'start_addr': 337927L, 'name': '_IOHIDEventQueueCreate', 'len': 890L}
{'start_addr': 134257L, 'name': '_kcgen_adjustKextSegmentLocations', 'len': 910L}
{'start_addr': 418454L, 'name': '___OSKextCheckProperty', 'len': 922L}
{'start_addr': 271941L, 'name': '___IOHIDEventEventCopyDebugDescWithIndentLevel', 'len': 940L}
{'start_addr': 528746L, 'name': '_io_connect_async_method', 'len': 963L}
{'start_addr': 489501L, 'name': '_offloadAssertions', 'len': 971L}
{'start_addr': 502758L, 'name': '_IOEthernetControllerCreate', 'len': 982L}
{'start_addr': 163763L, 'name': '__ZNSt3__118__insertion_sort_3IRNS_6__lessIN4TrieI10ExportInfoE15EntryWithOffsetES5_EEPS5_EEvT0_S9_T_', 'len': 1005L}
{'start_addr': 17819L, 'name': '_getTag', 'len': 1010L}
{'start_addr': 80067L, 'name': '_IOFBAcknowledgePM', 'len': 1013L}
{'start_addr': 279127L, 'name': '___IOHIDEventTypeDescriptorGameController', 'len': 1015L}
{'start_addr': 292890L, 'name': '___IOHIDEventSystemClientRefresh', 'len': 1020L}
{'start_addr': 408867L, 'name': '_OSKextGenerateDebugSymbols', 'len': 1034L}
{'start_addr': 325597L, 'name': '___IOHIDServiceNotification', 'len': 1063L}
{'start_addr': 282779L, 'name': '___IOHIDEventSystemEventCallback', 'len': 1068L}
{'start_addr': 104982L, 'name': '_CheckTimingWithRange', 'len': 1070L}
{'start_addr': 10841L, 'name': '_DoCFSerializeBinary', 'len': 1075L}
{'start_addr': 336669L, 'name': '___IOHIDSessionDispatchEvent', 'len': 1112L}
{'start_addr': 4241L, 'name': '_IOCFSerialize', 'len': 1139L}
{'start_addr': 341540L, 'name': '_OSKextParseVersionString', 'len': 1144L}
{'start_addr': 389498L, 'name': '___OSKextMapExecutable', 'len': 1146L}
{'start_addr': 140104L, 'name': '__ZN5kcgen8AdjustorI9Pointer32I12LittleEndianEE18adjustDataPointersERNSt3__16vectorIPvNS5_9allocatorIS7_EEEE', 'len': 1152L}
{'start_addr': 177964L, 'name': '__ZN5kcgen8AdjustorI9Pointer64I12LittleEndianEE18adjustDataPointersERNSt3__16vectorIPvNS5_9allocatorIS7_EEEE', 'len': 1152L}
{'start_addr': 364608L, 'name': '___OSKextCreateFromIdentifierCacheDict', 'len': 1155L}
{'start_addr': 356573L, 'name': '___OSKextInitialize', 'len': 1171L}
{'start_addr': 494855L, 'name': '_IOPMAssertionCreateWithProperties', 'len': 1175L}
{'start_addr': 70988L, 'name': '_IOFramebufferServerFinishOpen', 'len': 1182L}
{'start_addr': 332734L, 'name': '__IOHIDSessionSetPropertyForClient', 'len': 1183L}
{'start_addr': 327950L, 'name': '_IOHIDSessionCreate', 'len': 1209L}
{'start_addr': 362066L, 'name': '__OSKextReadFromIdentifierCacheForFolder', 'len': 1231L}
{'start_addr': 280923L, 'name': '_IOHIDEventSystemCreate', 'len': 1235L}
{'start_addr': 393082L, 'name': '_OSKextResolveDependencies', 'len': 1242L}
{'start_addr': 381030L, 'name': '___OSKextReadInfoDictionary', 'len': 1245L}
{'start_addr': 32763L, 'name': '_IOCreatePlugInInterfaceForService', 'len': 1285L}
{'start_addr': 363297L, 'name': '__OSKextReadCache', 'len': 1311L}
{'start_addr': 478396L, 'name': '__IOHIDEventSystemConnectionCopyRecord', 'len': 1340L}
{'start_addr': 168008L, 'name': '__ZN4TrieI10ExportInfoE8addEntryERKNSt3__112basic_stringIcNS2_11char_traitsIcEENS2_9allocatorIcEEEENS2_11__wrap_iterIPKcEES0_', 'len': 1366L}
{'start_addr': 387196L, 'name': '_OSKextCopyContainerForPluginKext', 'len': 1373L}
{'start_addr': 360323L, 'name': '___OSKextCreateKextsFromURL', 'len': 1378L}
{'start_addr': 38960L, 'name': '_getSystemProvidedPreferences', 'len': 1401L}
{'start_addr': 456585L, 'name': '___OSKextValidateIOKitPersonalityApplierFunction', 'len': 1415L}
{'start_addr': 310019L, 'name': '__IOHIDServiceCreate', 'len': 1444L}
{'start_addr': 114224L, 'name': '_InstallFromEDIDDesc', 'len': 1461L}
{'start_addr': 425430L, 'name': '___OSKextCreateKextsFromMkext', 'len': 1481L}
{'start_addr': 65410L, 'name': '_GetSymbolFromPEF', 'len': 1502L}
{'start_addr': 308513L, 'name': '___IOHIDServiceInit', 'len': 1506L}
{'start_addr': 470696L, 'name': '__IOHIDEventSystemConnectionCreate', 'len': 1518L}
{'start_addr': 469069L, 'name': '___IOHIDServiceClientCopyDebugDescription', 'len': 1558L}
{'start_addr': 416884L, 'name': '___OSKextValidate', 'len': 1570L}
{'start_addr': 5871L, 'name': '_DoCFSerialize', 'len': 1775L}
{'start_addr': 63610L, 'name': '__PEFExamineFile', 'len': 1800L}
{'start_addr': 366911L, 'name': '___OSKextProcessInfoDictionary', 'len': 1865L}
{'start_addr': 344057L, 'name': '__appendPlist', 'len': 1894L}
{'start_addr': 454404L, 'name': '___OSKextPerformLink', 'len': 1902L}
{'start_addr': 164768L, 'name': '__ZNSt3__127__insertion_sort_incompleteIRNS_6__lessIN4TrieI10ExportInfoE15EntryWithOffsetES5_EEPS5_EEbT0_S9_T_', 'len': 1916L}
{'start_addr': 76121L, 'name': '_IOFBInstallMode', 'len': 1929L}
{'start_addr': 317023L, 'name': '___IOHIDServiceEventCallback', 'len': 1982L}
{'start_addr': 141746L, 'name': '__ZN5kcgen8AdjustorI9Pointer32I12LittleEndianEE30rebuildLinkEditAndLoadCommandsEv', 'len': 1994L}
{'start_addr': 179610L, 'name': '__ZN5kcgen8AdjustorI9Pointer64I12LittleEndianEE30rebuildLinkEditAndLoadCommandsEv', 'len': 1994L}
{'start_addr': 330671L, 'name': '__IOHIDSessionGetPropertyForClient', 'len': 2023L}
{'start_addr': 371435L, 'name': '__OSKextWriteCache', 'len': 2046L}
{'start_addr': 158921L, 'name': '__ZNSt3__17__sort4IRNS_6__lessIN4TrieI10ExportInfoE15EntryWithOffsetES5_EEPS5_EEjT0_S9_S9_S9_T_', 'len': 2106L}
{'start_addr': 405269L, 'name': '_OSKextLoadWithOptions', 'len': 2203L}
{'start_addr': 7646L, 'name': '_IOCFUnserializeBinary', 'len': 2230L}
{'start_addr': 274026L, 'name': '___IOHIDEventTypeDescriptorDigitizer', 'len': 2262L}
{'start_addr': 181604L, 'name': '__ZN5kcgen8AdjustorI9Pointer64I12LittleEndianEE15adjustReferenceEjPhyyxxyyRNSt3__16vectorIPvNS6_9allocatorIS8_EEEERPjRjRy', 'len': 2364L}
{'start_addr': 143932L, 'name': '__ZN5kcgen8AdjustorI9Pointer32I12LittleEndianEE15adjustReferenceEjPhyyxxyyRNSt3__16vectorIPvNS6_9allocatorIS8_EEEERPjRjRy', 'len': 2374L}
{'start_addr': 252355L, 'name': '_IOHIDEventGetFloatValueWithOptions', 'len': 2485L}
{'start_addr': 124652L, 'name': '_InstallTimingForResolution', 'len': 2498L}
{'start_addr': 254855L, 'name': '_IOHIDEventGetDoubleValueWithOptions', 'len': 2629L}
{'start_addr': 422658L, 'name': '___OSKextCreateMkext', 'len': 2632L}
{'start_addr': 161027L, 'name': '__ZNSt3__17__sort5IRNS_6__lessIN4TrieI10ExportInfoE15EntryWithOffsetES5_EEPS5_EEjT0_S9_S9_S9_S9_T_', 'len': 2736L}
{'start_addr': 175110L, 'name': '__ZN5kcgen8AdjustorI9Pointer64I12LittleEndianEE27adjustReferencesUsingInfoV2ERNSt3__16vectorIPvNS5_9allocatorIS7_EEEE', 'len': 2854L}
{'start_addr': 137244L, 'name': '__ZN5kcgen8AdjustorI9Pointer32I12LittleEndianEE27adjustReferencesUsingInfoV2ERNSt3__16vectorIPvNS5_9allocatorIS7_EEEE', 'len': 2860L}
{'start_addr': 265151L, 'name': '_IOHIDEventSetDoubleValueWithOptions', 'len': 3037L}
{'start_addr': 249083L, 'name': '_IOHIDEventGetIntegerValueWithOptions', 'len': 3257L}
{'start_addr': 155632L, 'name': '__ZNSt3__17__sort3IRNS_6__lessIN4TrieI10ExportInfoE15EntryWithOffsetES5_EEPS5_EEjT0_S9_S9_T_', 'len': 3289L}
{'start_addr': 394324L, 'name': '___OSKextResolveDependencies', 'len': 3419L}
{'start_addr': 399819L, 'name': '_OSKextFindLinkDependencies', 'len': 3569L}
{'start_addr': 257499L, 'name': '_IOHIDEventSetIntegerValueWithOptions', 'len': 3689L}
{'start_addr': 106052L, 'name': '_IODisplayInstallTimings', 'len': 3932L}
{'start_addr': 261203L, 'name': '_IOHIDEventSetFloatValueWithOptions', 'len': 3933L}
{'start_addr': 109984L, 'name': '_LookExtensions', 'len': 4058L}
{'start_addr': 82414L, 'name': '_IOFBRebuild', 'len': 4541L}
{'start_addr': 150731L, 'name': '__ZNSt3__16__sortIRNS_6__lessIN4TrieI10ExportInfoE15EntryWithOffsetES5_EEPS5_EEvT0_S9_T_', 'len': 4901L}
{'start_addr': 12200L, 'name': '_IOCFUnserializeparse', 'len': 5124L}
{'start_addr': 116160L, 'name': '__IODisplayCreateInfoDictionary', 'len': 7676L}
{'start_addr': 93317L, 'name': '_IOFBBuildModeList', 'len': 8930L}
{'start_addr': 426960L, 'name': '_OSKextCreatePrelinkedKernel', 'len': 11352L}
{'start_addr': 438469L, 'name': '___OSKextPrelinkSplitKexts', 'len': 11867L}
'''
