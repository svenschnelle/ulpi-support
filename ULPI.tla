PREAMBLE 
/////////////////////////////////////////////////////////////////////////  
//  WARNING   WARNING   WARNING   WARNING   WARNING   WARNING   WARNING	    
//  WARNING   WARNING   WARNING   WARNING   WARNING   WARNING   WARNING		
//																			
//  DO NOT EDIT THIS FILE!													
//  Loading an edited TLA file in the TLA 700 application can				
//  cause the application to crash.  Editing this file can not				
//  only introduce errors in the text portion of the file but				
//  most editors (e.g. Notepad) will silently corrupt the binary			
//  data portion of the file, causing the TLA 700 application to			
//  crash when the corrupted file is loaded by the application.				
//																			
//  WARNING   WARNING   WARNING   WARNING   WARNING   WARNING   WARNING		
//  WARNING   WARNING   WARNING   WARNING   WARNING   WARNING   WARNING		
//																			
/////////////////////////////////////////////////////////////////////////
CafcCompositeCell "Preamble" "$$" {
	CafcStringCell "UserComment" "$$" = { "This is a saved module file."  }
	CafcByteCell "FileType" "$$" = { 1  }
	CafcArrayCell "InstrumentAfcNames" "$$" {
		CafcStringCell "NoName" "$$" = { "InstJup1"  }
	}
	CafcArrayCell "InstrumentUserNames" "$$" {
		CafcStringCell "NoName" "$$" = { "ULPI"  }
	}
	CafcArrayCell "ModuleFilterNames" "$$" {
		CafcStringCell "NoName" "$$" = { "ULPI - Filter"  }
	}
	CafcArrayCell "InstrumentSamples" "$$" {
		CafcLongCell "NoName" "$$" = { -1  }
	}
	CafcArrayCell "InstrumentExistingSamples" "$$" {
		CafcLongCell "NoName" "$$" = { -1  }
	}
	CafcArrayCell "InstrumentTypes" "$$" {
		CafcByteCell "NoName" "$$" = { 20  }
	}
	CafcStringCell "ProductVersionNoString" "$$" = { "5.8.112.0"  }
}
CapRoot "Root" "$$" {
	CjmInstrument "InstJup1" "$ULPI$" {
		CafcLongLongCell "SysTrigTime" "$$" = { 51872375  }
		CafcLongLongCell "SysExpOffsetTime" "$$" = { 0  }
		CafcStringCell "UserName" "$$" = { "ULPI"  }
		CafcLongLongCell "TimeSkew" "$$" = { 0  }
		CcmSaveDataCompositeCell "TbTimebaseSet" "$$" {
			CjmTimebaseData "TbMainTimebaseData" "$$" {
				CafcLongCell "DaNumSamples" "$$" = { 65538  }
				CafcLongCell "DaBytesPerSample" "$$" = { 26  }
				CafcByteCell "DaFinalState" "$$" = { 1  }
				CafcBooleanCell "DaTrigPresent" "$$" = { TRUE  }
				CafcLongCell "DaTrigSample" "$$" = { 1  }
				CafcLongLongCell "DaTrigSampleTime" "$$" = { 51872375  }
				CafcByteCell "DaTrigType" "$$" = { 1  }
				CafcBooleanCell "DaTrigAll" "$$" = { TRUE  }
				CafcLongLongCell "DaFirstSampleTime" "$$" = { 51789000  }
				CafcLongLongCell "DaLastSampleTime" "$$" = { 3519648258500  }
				CafcLongCell "DaStartDate" "$$" = { 1358714471  }
				CafcLongLongCell "DaTimeStampTick" "$$" = { 125  }
				CafcLongLongCell "DaSamplePeriod" "$$" = { 2000  }
				CafcBooleanCell "DaAsyncDataClock" "$$" = { FALSE  }
				CcmDataSet "DaSetNormal" "$$" {
					CafcBooleanCell "DaValid" "$$" = { TRUE  }
				}
				CcmDataSet "DaSetViolation" "$$" {
					CafcBooleanCell "DaValid" "$$" = { FALSE  }
				}
				CafcByteCell "jmCtmr1Mode" "$$" = { 0  }
				CafcLongLongCell "jmCtmr1Value" "$$" = { 0  }
				CafcByteCell "jmCtmr2Mode" "$$" = { 0  }
				CafcLongLongCell "jmCtmr2Value" "$$" = { 0  }
				CafcLongLongCell "jmCurSyncSpeed" "$$" = { 450000000  }
				CafcByteCell "jmStatusBitType" "$$" = { 3  }
				CafcByteCell "jmClkMode" "$$" = { 1  }
				CafcLongCell "jmTimestampReplicant" "$$" = { 0  }
				CafcLongLongCell "jmTimestampOffset" "$$" = { 2000  }
				CafcBooleanCell "jmDemuxClkQual" "$$" = { TRUE  }
				CafcByteCell "jmSanitizeMode" "$$" = { 0  }
				CjmCompareData "CmpData" "$$" {
					CafcBooleanCell "CmpEnable" "$$" = { FALSE  }
					CafcBooleanCell "CmpRuntimeEnable" "$$" = { FALSE  }
					CafcByteCell "CmpRuntimeCond" "$$" = { 0  }
					CcmSavedInstRef "CmpRefSource" "$$" {
						CafcStringCell "SavedInstRef" "$$" = { "LA 2"  }
					}
					CafcBooleanCell "CmpAllData" "$$" = { TRUE  }
					CafcByteCell "CmpStartRef" "$$" = { 2  }
					CafcLongCell "CmpStartSample" "$$" = { 0  }
					CafcLongCell "CmpCount" "$$" = { 0  }
					CafcByteCell "CmpAlignRef" "$$" = { 1  }
					CafcLongCell "CmpAlignOffset" "$$" = { 0  }
				}
				CafcArrayCell "CmpSuppression" "$$" {
				}
				CafcByteCell "CmpSupOpMode" "$$" = { 0  }
				CafcLongLongCell "CmpSupOpCount" "$$" = { 1024  }
				CafcBooleanCell "CmpSupTrigRelative" "$$" = { TRUE  }
				CafcBooleanCell "smSaveSystemType" "$$" = { FALSE  }
				CafcLongCell "JmXFactor" "$$" = { 1  }
				CafcLongCell "JmDataExpansionFactor" "$$" = { 1  }
				CafcBooleanCell "JmXIsWideStorage" "$$" = { FALSE  }
				CafcBooleanCell "JmHasGapCounters" "$$" = { FALSE  }
			}
			CjmTimebaseData "TbHiResTimebaseData" "$$" {
				CafcLongCell "DaNumSamples" "$$" = { 16320  }
				CafcLongCell "DaBytesPerSample" "$$" = { 17  }
				CafcByteCell "DaFinalState" "$$" = { 1  }
				CafcBooleanCell "DaTrigPresent" "$$" = { TRUE  }
				CafcLongCell "DaTrigSample" "$$" = { 8196  }
				CafcLongLongCell "DaTrigSampleTime" "$$" = { 51872375  }
				CafcByteCell "DaTrigType" "$$" = { 1  }
				CafcBooleanCell "DaTrigAll" "$$" = { TRUE  }
				CafcLongLongCell "DaFirstSampleTime" "$$" = { 50847875  }
				CafcLongLongCell "DaLastSampleTime" "$$" = { 52887750  }
				CafcLongCell "DaStartDate" "$$" = { 1358714471  }
				CafcLongLongCell "DaTimeStampTick" "$$" = { 125  }
				CafcLongLongCell "DaSamplePeriod" "$$" = { 125  }
				CafcBooleanCell "DaAsyncDataClock" "$$" = { TRUE  }
				CcmDataSet "DaSetNormal" "$$" {
					CafcBooleanCell "DaValid" "$$" = { TRUE  }
				}
				CafcLongCell "JmXFactor" "$$" = { 1  }
				CafcLongCell "JmDataExpansionFactor" "$$" = { 1  }
				CafcBooleanCell "JmXIsWideStorage" "$$" = { FALSE  }
				CafcBooleanCell "JmHasGapCounters" "$$" = { FALSE  }
				CcmDataSet "DaSetViolation" "$$" {
					CafcBooleanCell "DaValid" "$$" = { FALSE  }
				}
			}
		}
		CjmConfig "CommonConfigModel" "$$" {
			CafcLongCell "CoNumModules" "$$" = { 1  }
			CafcLongCell "CoNumChannels" "$$" = { 136  }
			CafcLongLongCell "CoMaxSyncRate" "$$" = { 450000000  }
			CafcLongLongCell "CoMaxSampleRate" "$$" = { 2000  }
			CafcLongCell "CoMaxDepth" "$$" = { 33554432  }
			CafcBooleanCell "CoEnabled" "$$" = { TRUE  }
			CafcLongLongCell "CoStzOffset" "$$" = { 0  }
			CafcLongCell "jmConfigMasterWidth" "$$" = { 136  }
			CafcLongCell "jmConfigSlaveWidth" "$$" = { 0  }
			CafcLongCell "jmConfigSlave2Width" "$$" = { 0  }
			CafcLongCell "jmConfigSlave3Width" "$$" = { 0  }
			CafcLongCell "jmConfigSlave4Width" "$$" = { 0  }
			CafcByteCell "jmSeries" "$$" = { 2  }
			CafcLongLongCell "jmMagnivuPeriod" "$$" = { 125  }
			CafcLongCell "jmMagnivuDepth" "$$" = { 16384  }
			CafcLongCell "jmWordRecDataSize" "$$" = { 17  }
			CafcLongCell "jmWordRecStatusSize" "$$" = { 1  }
			CafcArrayCell "jmDisplayStatusBitList" "$$" {
				CafcByteCell "NoName" "$$" = { 3  }
				CafcByteCell "NoName" "$$" = { 5  }
				CafcByteCell "NoName" "$$" = { 4  }
			}
			CafcArrayCell "jmTriggerStatusBitList" "$$" {
				CafcByteCell "NoName" "$$" = { 3  }
			}
			CafcBooleanCell "jmCustomRestoreFlag" "$$" = { FALSE  }
		}
		CjmScreenParam "jmScreenParams" "$$" {
			CcmToolbarParamSet "cmToolbarParamSet" "$$" {
				CafcBooleanCell "cmToolbarParamSetUseDefault" "$$" = { FALSE  }
				CcmToolbarParams "jsFileBarParams" "$$" {
					CafcBooleanCell "cmToolbarParamIsVisible" "$$" = { TRUE  }
					CafcBooleanCell "cmToolbarParamIsFloating" "$$" = { FALSE  }
					CafcLongCell "cmToolbarParamDockSide" "$$" = { 59419  }
					CafcLongCell "cmToolbarParamXPos" "$$" = { -2  }
					CafcLongCell "cmToolbarParamYPos" "$$" = { 0  }
				}
				CcmToolbarParams "jsSetupBarParams" "$$" {
					CafcBooleanCell "cmToolbarParamIsVisible" "$$" = { TRUE  }
					CafcBooleanCell "cmToolbarParamIsFloating" "$$" = { FALSE  }
					CafcLongCell "cmToolbarParamDockSide" "$$" = { 59419  }
					CafcLongCell "cmToolbarParamXPos" "$$" = { 99  }
					CafcLongCell "cmToolbarParamYPos" "$$" = { 0  }
				}
			}
			CafcLongCell "FrameWidth" "$$" = { 554  }
			CafcLongCell "FrameHeight" "$$" = { 492  }
			CafcLongCell "FrameXPos" "$$" = { 566  }
			CafcLongCell "FrameYPos" "$$" = { 401  }
			CafcByteCell "ShowState" "$$" = { 3  }
			CafcByteCell "jmSParamSetupChannelsVisible" "$$" = { 1  }
			CafcByteCell "jmSParamSetupShowGroups" "$$" = { 0  }
		}
		CcmWindowParams "jmTrigScreenParams" "$$" {
			CcmToolbarParamSet "cmToolbarParamSet" "$$" {
				CafcBooleanCell "cmToolbarParamSetUseDefault" "$$" = { FALSE  }
				CcmToolbarParams "jtFileBarParams" "$$" {
					CafcBooleanCell "cmToolbarParamIsVisible" "$$" = { TRUE  }
					CafcBooleanCell "cmToolbarParamIsFloating" "$$" = { FALSE  }
					CafcLongCell "cmToolbarParamDockSide" "$$" = { 59419  }
					CafcLongCell "cmToolbarParamXPos" "$$" = { -2  }
					CafcLongCell "cmToolbarParamYPos" "$$" = { 0  }
				}
				CcmToolbarParams "jtAddStateBarParams" "$$" {
					CafcBooleanCell "cmToolbarParamIsVisible" "$$" = { TRUE  }
					CafcBooleanCell "cmToolbarParamIsFloating" "$$" = { FALSE  }
					CafcLongCell "cmToolbarParamDockSide" "$$" = { 59419  }
					CafcLongCell "cmToolbarParamXPos" "$$" = { 76  }
					CafcLongCell "cmToolbarParamYPos" "$$" = { 0  }
				}
				CcmToolbarParams "jtEditBarParams" "$$" {
					CafcBooleanCell "cmToolbarParamIsVisible" "$$" = { TRUE  }
					CafcBooleanCell "cmToolbarParamIsFloating" "$$" = { FALSE  }
					CafcLongCell "cmToolbarParamDockSide" "$$" = { 59419  }
					CafcLongCell "cmToolbarParamXPos" "$$" = { 131  }
					CafcLongCell "cmToolbarParamYPos" "$$" = { 0  }
				}
				CcmToolbarParams "jtStorageBarParams" "$$" {
					CafcBooleanCell "cmToolbarParamIsVisible" "$$" = { TRUE  }
					CafcBooleanCell "cmToolbarParamIsFloating" "$$" = { FALSE  }
					CafcLongCell "cmToolbarParamDockSide" "$$" = { 59419  }
					CafcLongCell "cmToolbarParamXPos" "$$" = { 209  }
					CafcLongCell "cmToolbarParamYPos" "$$" = { 0  }
				}
				CcmToolbarParams "jtTrigPosBarParams" "$$" {
					CafcBooleanCell "cmToolbarParamIsVisible" "$$" = { TRUE  }
					CafcBooleanCell "cmToolbarParamIsFloating" "$$" = { FALSE  }
					CafcLongCell "cmToolbarParamDockSide" "$$" = { 59419  }
					CafcLongCell "cmToolbarParamXPos" "$$" = { 476  }
					CafcLongCell "cmToolbarParamYPos" "$$" = { 0  }
				}
				CcmToolbarParams "jtMagniVuBarParams" "$$" {
					CafcBooleanCell "cmToolbarParamIsVisible" "$$" = { TRUE  }
					CafcBooleanCell "cmToolbarParamIsFloating" "$$" = { FALSE  }
					CafcLongCell "cmToolbarParamDockSide" "$$" = { 59419  }
					CafcLongCell "cmToolbarParamXPos" "$$" = { -2  }
					CafcLongCell "cmToolbarParamYPos" "$$" = { 24  }
				}
			}
			CafcLongCell "FrameWidth" "$$" = { 640  }
			CafcLongCell "FrameHeight" "$$" = { 450  }
			CafcLongCell "FrameXPos" "$$" = { 20  }
			CafcLongCell "FrameYPos" "$$" = { 20  }
			CafcByteCell "ShowState" "$$" = { 6  }
		}
		CjmJupiterChannelInfo "CiChannelInfo" "$$" {
			CjmChannelArray "CiChannels" "$$" {
				CjmChannel "A3_5" "$DATAVALID$" {
					CafcStringCell "jmAsyncName" "$$" = { "DATAVALID"  }
				}
				CjmChannel "A3_4" "$PID$" {
					CafcStringCell "jmAsyncName" "$$" = { "PID"  }
				}
				CjmChannel "A3_3" "$RXCMDVALID$" {
					CafcStringCell "jmAsyncName" "$$" = { "RXCMDVALID"  }
				}
				CjmChannel "A3_2" "$DIR$" {
					CafcStringCell "jmAsyncName" "$$" = { "DIR"  }
				}
				CjmChannel "A3_1" "$STP$" {
					CafcStringCell "jmAsyncName" "$$" = { "STP"  }
				}
				CjmChannel "A3_0" "$NXT$" {
					CafcStringCell "jmAsyncName" "$$" = { "NXT"  }
				}
				CjmChannel "A2_7" "$D7$" {
					CafcStringCell "jmAsyncName" "$$" = { "D7"  }
				}
				CjmChannel "A2_6" "$D6$" {
					CafcStringCell "jmAsyncName" "$$" = { "D6"  }
				}
				CjmChannel "A2_5" "$D5$" {
					CafcStringCell "jmAsyncName" "$$" = { "D5"  }
				}
				CjmChannel "A2_4" "$D4$" {
					CafcStringCell "jmAsyncName" "$$" = { "D4"  }
				}
				CjmChannel "A2_3" "$D3$" {
					CafcStringCell "jmAsyncName" "$$" = { "D3"  }
				}
				CjmChannel "A2_2" "$D2$" {
					CafcStringCell "jmAsyncName" "$$" = { "D2"  }
				}
				CjmChannel "A2_1" "$D1$" {
					CafcStringCell "jmAsyncName" "$$" = { "D1"  }
				}
				CjmChannel "A2_0" "$D0$" {
					CafcStringCell "jmAsyncName" "$$" = { "D0"  }
				}
				CjmChannel "CK0" "$CLK$" {
					CafcStringCell "jmAsyncName" "$$" = { "CLK"  }
				}
			}
			CafcBooleanCell "jmInitAsyncForCustom" "$$" = { FALSE  }
			CjmProbeSet "jmProbeSet" "$$" {
				CafcLongLongCell "jmDefaultThreshold" "$$" = { 1500000000000  }
			}
			CjmUserGroups "jmUserGroups" "$$" {
				CjmChannelGroup "1UserGrp" "$CK0$" {
					CafcStringCell "UserName" "$$" = { "CK0"  }
					CafcBooleanCell "ClaAMSgenerated" "$$" = { FALSE  }
					CafcBooleanCell "ClaAMSonOff" "$$" = { TRUE  }
					CafcByteCell "ClaAMSradix" "$$" = { 0  }
					CafcStringCell "ClaAMSsymFileName" "$$" = { ""  }
					CafcBooleanCell "ClaAppGenerated" "$$" = { FALSE  }
					CafcStringCell "ClaGroupDefinition" "$$" = { "CLK"  }
				}
				CjmChannelGroup "2UserGrp" "$CTRL$" {
					CafcStringCell "UserName" "$$" = { "CTRL"  }
					CafcBooleanCell "ClaAMSgenerated" "$$" = { FALSE  }
					CafcBooleanCell "ClaAMSonOff" "$$" = { TRUE  }
					CafcByteCell "ClaAMSradix" "$$" = { 0  }
					CafcStringCell "ClaAMSsymFileName" "$$" = { ""  }
					CafcBooleanCell "ClaAppGenerated" "$$" = { FALSE  }
					CafcStringCell "ClaGroupDefinition" "$$" = { "DATAVALID,PID,RXCMDVALID,STP,NXT,DIR"  }
				}
				CjmChannelGroup "3UserGrp" "$DATA$" {
					CafcStringCell "UserName" "$$" = { "DATA"  }
					CafcBooleanCell "ClaAMSgenerated" "$$" = { FALSE  }
					CafcBooleanCell "ClaAMSonOff" "$$" = { TRUE  }
					CafcByteCell "ClaAMSradix" "$$" = { 0  }
					CafcStringCell "ClaAMSsymFileName" "$$" = { ""  }
					CafcBooleanCell "ClaAppGenerated" "$$" = { FALSE  }
					CafcStringCell "ClaGroupDefinition" "$$" = { "D7,D6,D5,D4,D3,D2,D1,D0"  }
				}
			}
			CjmAnalogMux "jmAnalogMux" "$$" {
				CafcCompositeCell "m0c0" "$$" {
					CafcStringCell "jmFeedName" "$$" = { "CK0"  }
					CafcLongLongCell "jmFeedDelay" "$$" = { -7745  }
					CafcLongCell "jmFeedAttenuation" "$$" = { 10  }
				}
				CafcCompositeCell "m0c1" "$$" {
					CafcStringCell "jmFeedName" "$$" = { "A3_7"  }
					CafcLongLongCell "jmFeedDelay" "$$" = { -7963  }
					CafcLongCell "jmFeedAttenuation" "$$" = { 10  }
				}
				CafcCompositeCell "m0c2" "$$" {
					CafcStringCell "jmFeedName" "$$" = { "A3_6"  }
					CafcLongLongCell "jmFeedDelay" "$$" = { -7658  }
					CafcLongCell "jmFeedAttenuation" "$$" = { 10  }
				}
				CafcCompositeCell "m0c3" "$$" {
					CafcStringCell "jmFeedName" "$$" = { "A3_5"  }
					CafcLongLongCell "jmFeedDelay" "$$" = { -8028  }
					CafcLongCell "jmFeedAttenuation" "$$" = { 10  }
				}
			}
		}
		CcmSupportedLA "SupportedLA" "$$" {
			CafcStringCell "PackageName" "$$" = { "ULPI"  }
			RDAInternalOpMarkSet "RDAOpMarkSet" "$$" {
			}
		}
		CjmClock "jmClk" "$$" {
			CafcByteCell "jmClkMode" "$$" = { 1  }
			CjmAsyncClock "jmAsyncClock" "$$" {
				CafcLongLongCell "jmClkIntRate" "$$" = { 2000  }
			}
			CafcCompositeCell "jmSyncClock" "$$" {
				CafcByteCell "jmSyncClockType" "$$" = { 1  }
				CafcCompositeCell "jmSingleSyncClock" "$$" {
					CafcLongLongCell "jmSUTClockRate" "$$" = { 450000000  }
					CafcLongLongCell "jmMaxDataRate" "$$" = { 450000000  }
					CafcStringCell "jmClockChanName" "$$" = { "CK0()"  }
					CjmExternalPresets "jmSingleClockPresets" "$$" {
						CjmUIChannelPresets "jmClkExtChannelPresets" "$$" {
						}
						CafcLongLongCell "jmDefaultSetup1" "$$" = { 0  }
						CafcLongLongCell "jmDefaultHold1" "$$" = { 625  }
						CafcLongLongCell "jmDefaultSetup3" "$$" = { 0  }
						CafcLongLongCell "jmDefaultHold3" "$$" = { 625  }
					}
					CjmSingleSyncSamplePts "jmSingleSyncSamplePts" "$$" {
						CafcByteCell "jmSamplePointsStateCell" "$$" = { 0  }
					}
				}
				CafcCompositeCell "jmComplexSyncClock" "$$" {
					CjmClockDefinition "jmClkGPSyncAdv1Clk" "$$" {
						CafcArrayCell "jmClkGPSyncDef" "$$" {
							CafcArrayCell "" "$$" {
								CafcByteCell "CK0()" "$$" = { 0  }
								CafcByteCell "" "$$" = { 4  }
								CafcByteCell "" "$$" = { 4  }
								CafcByteCell "" "$$" = { 4  }
								CafcByteCell "" "$$" = { 4  }
							}
							CafcArrayCell "" "$$" {
								CafcByteCell "" "$$" = { 4  }
								CafcByteCell "" "$$" = { 4  }
								CafcByteCell "" "$$" = { 4  }
								CafcByteCell "" "$$" = { 4  }
								CafcByteCell "" "$$" = { 4  }
							}
							CafcArrayCell "" "$$" {
								CafcByteCell "" "$$" = { 4  }
								CafcByteCell "" "$$" = { 4  }
								CafcByteCell "" "$$" = { 4  }
								CafcByteCell "" "$$" = { 4  }
								CafcByteCell "" "$$" = { 4  }
							}
							CafcArrayCell "" "$$" {
								CafcByteCell "" "$$" = { 4  }
								CafcByteCell "" "$$" = { 4  }
								CafcByteCell "" "$$" = { 4  }
								CafcByteCell "" "$$" = { 4  }
								CafcByteCell "" "$$" = { 4  }
							}
						}
					}
					CjmClockDefinition "jmClkGPSyncAdv2Clk" "$$" {
						CafcArrayCell "jmClkGPSyncDef" "$$" {
							CafcArrayCell "" "$$" {
								CafcByteCell "" "$$" = { 4  }
								CafcByteCell "" "$$" = { 4  }
								CafcByteCell "" "$$" = { 4  }
								CafcByteCell "" "$$" = { 4  }
								CafcByteCell "" "$$" = { 4  }
							}
							CafcArrayCell "" "$$" {
								CafcByteCell "" "$$" = { 4  }
								CafcByteCell "" "$$" = { 4  }
								CafcByteCell "" "$$" = { 4  }
								CafcByteCell "" "$$" = { 4  }
								CafcByteCell "" "$$" = { 4  }
							}
							CafcArrayCell "" "$$" {
								CafcByteCell "" "$$" = { 4  }
								CafcByteCell "" "$$" = { 4  }
								CafcByteCell "" "$$" = { 4  }
								CafcByteCell "" "$$" = { 4  }
								CafcByteCell "" "$$" = { 4  }
							}
							CafcArrayCell "" "$$" {
								CafcByteCell "" "$$" = { 4  }
								CafcByteCell "" "$$" = { 4  }
								CafcByteCell "" "$$" = { 4  }
								CafcByteCell "" "$$" = { 4  }
								CafcByteCell "" "$$" = { 4  }
							}
						}
					}
					CafcByteCell "jmMasterSamplerEdgeType" "$$" = { 0  }
					CafcByteCell "jmSecondarySamplerEdgeType" "$$" = { 9  }
					CjmExternalPresets "jmComplexClockPresets" "$$" {
						CafcLongLongCell "jmClkMaxSyncSpeed" "$$" = { -1  }
						CafcLongCell "jmClkDefHold" "$$" = { 0  }
						CjmUIChannelPresets "jmClkExtChannelPresets" "$$" {
						}
					}
					CafcArrayCell "jmComplexSyncSamplePts" "$$" {
						CafcByteCell "jmSamplePointsStateCell" "$$" = { 0  }
					}
					CafcLongLongCell "jmSUTClockRate" "$$" = { 450000000  }
					CafcLongLongCell "jmMaxDataRate" "$$" = { 450000000  }
				}
				CafcByteCell "jmLastSyncClockType" "$$" = { 1  }
			}
			CjmCustomClock "jmCustomClock" "$$" {
				CjmCustomOptions "jmClkCustOpts" "$$" {
					CafcStringCell "jmClkCustOptsFile" "$$" = { ""  }
					CafcArrayCell "jmClkCustOptsSels" "$$" {
					}
					CafcLongLongCell "jmClkSampleRate" "$$" = { 0  }
				}
				CjmCustomPresets "jmClkSetupHoldGroups" "$$" {
					CafcLongLongCell "jmClkMaxSyncSpeed" "$$" = { -1  }
					CafcByteCell "jmClkStatusBitType" "$$" = { 3  }
					CjmBanjoCustomChannelPresets "jmClkSHChannelPresets" "$$" {
					}
				}
				CafcLongLongCell "jmClkCustMaxClockRate" "$$" = { 450000000  }
			}
			CjmStatusTypeManager "jmClkStatusTypeManager" "$$" {
				CafcByteCell "JmSBMStatusTypeSaveRestore" "$$" = { 3  }
			}
			CjmAutoDeskew "JmAutoDeskew" "$$" {
				CafcLongLongCell "jmAutoDeskewRangeSetupTicks" "$$" = { 64  }
				CafcLongLongCell "jmAutoDeskewRangeHoldTicks" "$$" = { 64  }
				CafcLongLongCell "jmAutoDeskewQuality" "$$" = { 1000  }
				CafcLongLongCell "jmAutoDeskewMinQuality" "$$" = { 1000  }
				CafcLongLongCell "jmAutoDeskewMaxQuality" "$$" = { 25000000  }
				CafcStringCell "jmAutoDeskewConfigName" "$$" = { ""  }
				CafcStringCell "jmAutoDeskewSetupName" "$$" = { ""  }
				CafcByteCell "jmAutoDeskewClockMode" "$$" = { 1  }
			}
		}
		CcmFilters "Filters" "$$" {
			CcmFilter "Filter" "$Filter$" {
				CafcStringCell "UserName" "$$" = { "Filter"  }
				CafcStringCell "Description" "$$" = { ""  }
				CafcBooleanCell "FilterEnable" "$$" = { TRUE  }
				CcmFilterClauseDefs "FilterClauses" "$$" {
					CcmFilterClause "FilterClause" "$$" {
						CafcStringCell "UserName" "$$" = { ""  }
						CafcByteCell "FilterClauseType" "$$" = { 0  }
						CafcBooleanCell "FilterClauseDisable" "$$" = { FALSE  }
						CafcStringCell "GroupName" "$$" = { ""  }
						CafcLongCell "FilterForegroundColor" "$$" = { 0  }
						CafcLongCell "FilterBackgroundColor" "$$" = { 15658671  }
						CafcBooleanCell "FilterForegroundDisable" "$$" = { FALSE  }
						CafcBooleanCell "FilterBackgroundDisable" "$$" = { FALSE  }
						CcmFilterEventDefs "FilterEvents" "$$" {
							CcmFSEventLAGroup "FilterEvent" "$$" {
								CafcByteCell "SearchEventType" "$$" = { 0  }
								CafcBooleanCell "SearchEventBoolean" "$$" = { FALSE  }
								CafcStringCell "SearchElement" "$$" = { "CK0"  }
								CafcByteCell "SearchCondition" "$$" = { 0  }
								CafcStringCell "SearchArgument1" "$$" = { "X"  }
								CafcStringCell "SearchArgument2" "$$" = { "X"  }
								CafcLongCell "SearchDisasmCondition" "$$" = { 0  }
								CafcBooleanCell "SearchMatchCase" "$$" = { TRUE  }
								CafcByteCell "Radix" "$$" = { 2  }
							}
						}
					}
				}
			}
		}
		CjmTriggerInfo "jmTriggerInfo" "$$" {
			CjmTrigger "jmTriggerAsyncSync" "$$" {
				CcmSymbolFileLinks "SymbolFileLinks" "$$" {
				}
				CjmWordDefinitions "jmTrigWordDefinitions" "$$" {
				}
				CjmTransitionDefinitions "jmTrigTransitionDefinitions" "$$" {
				}
				CjmSnapshotDefinitions "jmTrigSnapshotDefinitions" "$$" {
				}
				CjmEventMacros "jmTrigEventMacros" "$$" {
					CjmEventMacro "jmEventMacro" "$ $" {
						CafcStringCell "jmMacroUserName" "$$" = { " "  }
						CafcStringCell "jmMacroString" "$$" = { "( Anything )"  }
						CafcByteCell "jmMacroDisplayMode" "$$" = { 1  }
					}
				}
				CjmStorage "jmStorage" "$$" {
					CafcByteCell "jmStorageAcqMode" "$$" = { 0  }
					CafcByteCell "jmStorageMode" "$$" = { 3  }
					CafcByteCell "jmStartStop" "$$" = { 0  }
					CafcByteCell "jmTriggerDelay" "$$" = { 50  }
					CafcByteCell "jmHiResDelay" "$$" = { 50  }
					CafcLongLongCell "jmStorageUserDepth" "$$" = { 131072  }
					CafcLongLongCell "jmStorageHiResDepth" "$$" = { 16320  }
					CafcBooleanCell "jmStorageForceMainPrefill" "$$" = { FALSE  }
					CafcLongLongCell "jmStorageHiResStoreRate" "$$" = { 125  }
					CjmStorageClause "jmStorageClause" "$$" {
						CafcStringCell "jmClauseUiCondition" "$$" = { "( Channel \"A3(5):U:DATAVALID\" = High ) Or ( Channel \"A3(3):U:RXCMDVALID\" = High )"  }
						CafcStringCell "jmClauseAction" "$$" = { "( StoreSample )"  }
						CafcStringCell "jmTrigClauseComment" "$$" = { ""  }
					}
				}
				CjmTriggerMachine "jmTriggerMachine" "$$" {
					CafcLongCell "jmTriggerStateCount" "$$" = { 1  }
					CjmTriggerStateArray "jmTriggerStateArray" "$$" {
						CjmTriggerState "jmTriggerState1" "$$" {
							CafcLongCell "jmTriggerClauseCount" "$$" = { 1  }
							CjmTriggerClauseArray "jmTriggerClauseArray" "$$" {
								CjmTriggerClause "jmTriggerClause1" "$$" {
									CafcStringCell "jmClauseUiCondition" "$$" = { "( Channel \"A3(4):U:PID\" Goes High )"  }
									CafcStringCell "jmClauseAction" "$$" = { "( TriggerAll )"  }
									CafcStringCell "jmTrigClauseComment" "$$" = { ""  }
								}
							}
							CafcStringCell "jmTrigStateComment" "$$" = { "Clicking 'Run\/Stop' button or a System trigger will trigger the LA module"  }
						}
					}
				}
				CjmTriggerChannels "jmTriggerChannels" "$$" {
					CjmBanjoTriggerChannel "CK0" "$$" {
						CafcLongLongCell "jtmTgSetupTime" "$$" = { 2000  }
						CafcLongLongCell "jtmTgHoldTime" "$$" = { 0  }
					}
				}
				CjmTriggerGroups "jmTriggerGroups" "$$" {
				}
				CafcByteCell "jmTabSplitWndPage" "$$" = { 1  }
				CafcBooleanCell "jmCommentsVisibleFlag" "$$" = { TRUE  }
				CafcStringCell "jmTrigOwnerID" "$$" = { "PT:ULPI"  }
				CafcBooleanCell "jmTrigToolbarVisibleFlag" "$$" = { TRUE  }
				CafcBooleanCell "jmTrigAdvToolbarVisibleFlag" "$$" = { TRUE  }
			}
			
			CjmTrigger "jmTriggerCustom" "$$" {
				CcmSymbolFileLinks "SymbolFileLinks" "$$" {
				}
				CjmWordDefinitions "jmTrigWordDefinitions" "$$" {
				}
				CjmTransitionDefinitions "jmTrigTransitionDefinitions" "$$" {
				}
				CjmSnapshotDefinitions "jmTrigSnapshotDefinitions" "$$" {
				}
				CjmEventMacros "jmTrigEventMacros" "$$" {
				}
				CjmStorage "jmStorage" "$$" {
					CafcByteCell "jmStorageAcqMode" "$$" = { 0  }
					CafcByteCell "jmStorageMode" "$$" = { 0  }
					CafcByteCell "jmStartStop" "$$" = { 0  }
					CafcByteCell "jmTriggerDelay" "$$" = { 50  }
					CafcByteCell "jmHiResDelay" "$$" = { 50  }
					CafcLongLongCell "jmStorageUserDepth" "$$" = { 131072  }
					CafcLongLongCell "jmStorageHiResDepth" "$$" = { 16320  }
					CafcBooleanCell "jmStorageForceMainPrefill" "$$" = { FALSE  }
					CafcLongLongCell "jmStorageHiResStoreRate" "$$" = { 125  }
					CjmStorageClause "jmStorageClause" "$$" {
						CafcStringCell "jmClauseUiCondition" "$$" = { "( Anything )"  }
						CafcStringCell "jmClauseAction" "$$" = { "( StoreSample )"  }
						CafcStringCell "jmTrigClauseComment" "$$" = { ""  }
					}
				}
				CjmTriggerMachine "jmTriggerMachine" "$$" {
					CafcLongCell "jmTriggerStateCount" "$$" = { 1  }
					CjmTriggerStateArray "jmTriggerStateArray" "$$" {
						CjmTriggerState "jmTriggerState1" "$$" {
							CafcLongCell "jmTriggerClauseCount" "$$" = { 1  }
							CjmTriggerClauseArray "jmTriggerClauseArray" "$$" {
								CjmTriggerClause "jmTriggerClause1" "$$" {
									CafcStringCell "jmClauseUiCondition" "$$" = { "( Anything )"  }
									CafcStringCell "jmClauseAction" "$$" = { "( TriggerSelf )"  }
									CafcStringCell "jmTrigClauseComment" "$$" = { ""  }
								}
							}
							CafcStringCell "jmTrigStateComment" "$$" = { ""  }
						}
					}
				}
				CjmTriggerChannels "jmTriggerChannels" "$$" {
				}
				CjmTriggerGroups "jmTriggerGroups" "$$" {
				}
				CafcByteCell "jmTabSplitWndPage" "$$" = { 0  }
				CafcBooleanCell "jmCommentsVisibleFlag" "$$" = { TRUE  }
				CafcStringCell "jmTrigOwnerID" "$$" = { "ET:LA 1"  }
			}
			
		}
	}
}
