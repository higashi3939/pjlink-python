#
# Copyright (C) 2023 higashi
# Released under the MIT license.
# Please see  https://opensource.org/licenses/MIT
#
# This script has been confirmed to work in the following environment.
#  - Windows 10 Pro 64bit
#  - VisualStudio Code 1.78.2
#  - Python 3.10.4 64bit
#  - Projectors:
#      SONY:VPL-CWZ10
#      NEC: NP-PE506UL, NP-P605UL
#


import PJLink
from enum import IntEnum

print("Program begin!")


# Settings for LAN
# Please change the following to your environment
TARGET_IP_STR = "192.168.2.100"
TARGET_PORT = PJLink.Const.DefaultTcpPort # 4352
COMM_TIMEOUT_SEC = 3.0


def listvalue_to_hexstring(list):
    length = len(list)
    if length <= 0:
        return "Conversion error!"
    else:
        out_str = ""
        cnt = 0
        for item in list:
            out_str += format(item, '02X')
            if cnt != (length - 1):
                out_str += " "
            cnt += 1
        return out_str


def listvalue_to_asciistring(list):
    length = len(list)
    if length <= 0:
        return "Conversion error!"
    else:
        out_str = ""
        cnt = 0
        for item in list:
            try:
                # ignore LF or CR
                if (item == 0x0A) or (item == 0x0D):
                    pass
                else:
                    out_str += str(item.to_bytes(1, 'little'), encoding='ascii', errors='strict')
                    #if cnt != (length - 1):
                    #    out_str += " "
            except Exception as e:
                print(e)
                out_str = "Conversion error!"
                break
            cnt += 1
        return out_str



class PJLink_TestCase(IntEnum):
    GET_POWER             = 1
    SET_POWER_OFF         = 2
    SET_POWER_ON          = 3
    GET_INPUT             = 4
    SET_INPUT             = 5
    GET_AVMUTE            = 6
    SET_AVMUTE            = 7
    GET_ERROR_STATUS      = 8  # Not has checked when the projector is in an actual error state.
    GET_LAMPNUM_AND_USAGE = 9  # This has only been confirmed with single lamp (laser) projector.
    GET_INPUT_LIST        = 10
    GET_PROJECTOR_NAME    = 11
    GET_MANUFACTURE_NAME  = 12
    GET_PRODUCT_NAME      = 13
    GET_OTHER_INFO        = 14
    GET_CLASS_INFO        = 15



def PJLink_TestProc(testcase):

    with PJLink.CommandControl_Class1() as pjlink:
        if pjlink.Connect(TARGET_IP_STR) == False:
            print("Connection error!")
            return False
        else:
            print("Connection established!")

        ## Test cases
        if testcase == PJLink_TestCase.GET_POWER:
            pjlink_result = pjlink.GetPower()
        elif testcase == PJLink_TestCase.SET_POWER_OFF:
            pjlink_result = pjlink.SetPower(False)
        elif testcase == PJLink_TestCase.SET_POWER_ON:
            pjlink_result = pjlink.SetPower(True)
        elif testcase == PJLink_TestCase.GET_INPUT:
            pjlink_result = pjlink.GetInput()
        elif testcase == PJLink_TestCase.SET_INPUT:
            # Please change to the terminal you want to use.
            terminal = PJLink.InputSource(PJLink.InputSource.InputType.DIGITAL, PJLink.InputSource.InputNumber.INPUT_1)
            pjlink_result = pjlink.SetInput(terminal)
        elif testcase == PJLink_TestCase.GET_AVMUTE:
            pjlink_result = pjlink.GetAVMute()
        elif testcase == PJLink_TestCase.SET_AVMUTE:
            # Please change to the mute setting you want to use.
            mute = PJLink.MuteSetting(PJLink.MuteSetting.MuteType.AudioAndVisualMute, PJLink.MuteSetting.MuteValue.Off)
            pjlink_result = pjlink.SetAVMute(mute)
        elif testcase == PJLink_TestCase.GET_ERROR_STATUS:
            pjlink_result = pjlink.GetErrorStatus()
        elif testcase == PJLink_TestCase.GET_LAMPNUM_AND_USAGE:
            pjlink_result = pjlink.GetLampNumAndUsageTime()
        elif testcase == PJLink_TestCase.GET_INPUT_LIST:
            pjlink_result = pjlink.GetInputTogglingList()
        elif testcase == PJLink_TestCase.GET_PROJECTOR_NAME:
            pjlink_result = pjlink.GetProjectorName()
        elif testcase == PJLink_TestCase.GET_MANUFACTURE_NAME:
            pjlink_result = pjlink.GetManufactureName()
        elif testcase == PJLink_TestCase.GET_PRODUCT_NAME:
            pjlink_result = pjlink.GetProductName()
        elif testcase == PJLink_TestCase.GET_OTHER_INFO:
            pjlink_result = pjlink.GetOtherInformation()
        elif testcase == PJLink_TestCase.GET_CLASS_INFO:
            pjlink_result = pjlink.GetClassInformation()
        else:
            print("Test case is error!")
            return False

        sent_packet = pjlink_result.GetAndCopySentPacket()
        recv_packet = pjlink_result.GetAndCopyReceivedPacket()
        print("Send: " + listvalue_to_asciistring(sent_packet))
        #print(listvalue_to_hexstring(sent_packet))
        print("Recv: " + listvalue_to_asciistring(recv_packet))
        #print(listvalue_to_hexstring(recv_packet))
        if pjlink_result.GetErrorCode() == PJLink.ErrorCode.NO_ERROR:
            print("PJLink Response: " + str(pjlink_result.GetPJLinkResponseCode()))
            print("PJLink Result: " + str(pjlink_result.GetPJLinkRequestResult()))
            return True
        else:
            print("PJLink Result: failed!")
            return False


def PJLink_GetAllInfo():
    ret = True
    if ret != False:
        print("")
        ret = PJLink_TestProc(PJLink_TestCase.GET_POWER)
    if ret != False:
        print("")
        ret = PJLink_TestProc(PJLink_TestCase.GET_INPUT)
    if ret != False:
        print("")
        ret = PJLink_TestProc(PJLink_TestCase.GET_AVMUTE)
    if ret != False:
        print("")
        ret = PJLink_TestProc(PJLink_TestCase.GET_ERROR_STATUS)
    if ret != False:
        print("")
        ret = PJLink_TestProc(PJLink_TestCase.GET_LAMPNUM_AND_USAGE)
    if ret != False:
        print("")
        ret = PJLink_TestProc(PJLink_TestCase.GET_INPUT_LIST)
    if ret != False:
        print("")
        ret = PJLink_TestProc(PJLink_TestCase.GET_PROJECTOR_NAME)
    if ret != False:
        print("")
        ret = PJLink_TestProc(PJLink_TestCase.GET_MANUFACTURE_NAME)
    if ret != False:
        print("")
        ret = PJLink_TestProc(PJLink_TestCase.GET_PROJECTOR_NAME)
    if ret != False:
        print("")
        ret = PJLink_TestProc(PJLink_TestCase.GET_OTHER_INFO)
    if ret != False:
        print("")
        ret = PJLink_TestProc(PJLink_TestCase.GET_CLASS_INFO)
    return ret


def main():
    #PJLink_TestProc(PJLink_TestCase.SET_POWER_ON)
    #PJLink_GetAllInfo()
    #PJLink_TestProc(PJLink_TestCase.SET_POWER_OFF)
    return None

    
if __name__ == "__main__":
    main()
    

print("Program end!")
