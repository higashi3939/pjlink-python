# 
# PJLink.py
#
# This is a program that controls Projectors with PJLink commands.
# This codes follows the PJLink Version 2.02 (2017.1.13) specification. 
# The command specifications refer to the following.
#  => https://pjlink.jbmia.or.jp/
#
# Copyright (C) 2023 higashi
# Released under the MIT license.
# Please see  https://opensource.org/licenses/MIT
# 

import copy
import time
import array
import hashlib # for MD5 calculation
from enum import Enum
from enum import IntEnum
from SocketCommTcpPy import SocketCommTcpPy


class ConnectionType(Enum):
    TCP = 0
    UNKNOWN = 0xff


class ErrorCode(Enum):
    UNKNOWN_ERROR = -99
    CONNECTION_ERROR = -1
    CONNECTION_TYPE_ERROR = -2
    SEND_ERROR = -10
    RECV_ERROR = -11
    RECV_NACK_ERROR = -22
    RECV_INVALID_PACKET_ERROR = -23
    RECV_INPUT_CHANGE_NOT_EXEC_ERROR = -30
    NO_ERROR = 0


class Const(IntEnum):
    DefaultTcpPort = 4352


class ResponseCode(Enum):
    NoError = 0
    UndefinedCommand = 1
    ParameterIsRangeOver = 2
    UnacceptablePeriod = 3
    DisplayDeviceIsError = 4
    NonExistentInput = 5
    AVMuteIsNotSupported = 6
    PasswordIsMismatch = 7
    NotHaveLamp = 8
    Indefinite = 0xff


class InputSource:
    
    class InputType(IntEnum):
        RGB = 0x31
        VIDEO = 0x32
        DIGITAL = 0x33
        STORAGE = 0x34
        NETWORK = 0x35
        # INTERNAL is class2

    class InputNumber(IntEnum):
        INPUT_1 = 0x31
        INPUT_2 = 0x32
        INPUT_3 = 0x33
        INPUT_4 = 0x34
        INPUT_5 = 0x35
        INPUT_6 = 0x36
        INPUT_7 = 0x37
        INPUT_8 = 0x38
        INPUT_9 = 0x39
        # A~Z are class2

    #Type = InputType.RGB
    #Number = InputNumber.INPUT_1

    def __init__(self, input_type, input_number):
        self.Type = input_type
        self.Number = input_number

    def __del__(self):
        pass

    def CanParseToInputType(check_value):
        result = False
        for v in InputSource.InputType:
            if v.value == check_value:
                result = True
                break
        return result

    def CanParseToInputNumber(check_value):
        result = False
        for v in InputSource.InputNumber:
            if v.value == check_value:
                result = True
                break
        return result

    def GetInputTypeString(value):
        ret = "Error"
        if InputSource.CanParseToInputType(value) == True:
            if value == InputSource.InputType.RGB:
                ret = "RGB"
            elif value == InputSource.InputType.VIDEO:
                ret = "VIDEO"
            elif value == InputSource.InputType.DIGITAL:
                ret = "DIGITAL"
            elif value == InputSource.InputType.STORAGE:
                ret = "STORAGE"
            elif value == InputSource.InputType.NETWORK:
                ret = "NETWORK"
            else: # Don't come here
                ret = "Unknown"
        return ret

    def GetInputNumberString(value):
        ret = "Error"
        if InputSource.CanParseToInputNumber(value) == True:
            if value == InputSource.InputNumber.INPUT_1:
                ret = "INPUT_1"
            elif value == InputSource.InputNumber.INPUT_2:
                ret = "INPUT_2"
            elif value == InputSource.InputNumber.INPUT_3:
                ret = "INPUT_3"
            elif value == InputSource.InputNumber.INPUT_4:
                ret = "INPUT_4"
            elif value == InputSource.InputNumber.INPUT_5:
                ret = "INPUT_5"
            elif value == InputSource.InputNumber.INPUT_6:
                ret = "INPUT_6"
            elif value == InputSource.InputNumber.INPUT_7:
                ret = "INPUT_7"
            elif value == InputSource.InputNumber.INPUT_8:
                ret = "INPUT_8"
            elif value == InputSource.InputNumber.INPUT_9:
                ret = "INPUT_9"
            else: # Don't come here
                ret = "Unknown"
        return ret


class MuteSetting:
    
    class MuteType(IntEnum):
        VisualMute = 0x31
        AudioMute = 0x32
        AudioAndVisualMute = 0x33

    class MuteValue(IntEnum):
        Off = 0x30
        On = 0x31

    #Type = MuteType.VisualMute
    #Value = MuteValue.Off

    def __init__(self, mute_type, mute_value):
        self.Type = mute_type
        self.Value = mute_value

    def __del__(self):
        pass

    def CanParseToMuteType(check_value):
        result = False
        for v in MuteSetting.MuteType:
            if v.value == check_value:
                result = True
                break
        return result

    def CanParseToMuteValue(check_value):
        result = False
        for v in MuteSetting.MuteValue:
            if v.value == check_value:
                result = True
                break
        return result

    def GetMuteTypeString(value):
        ret = "Error"
        if MuteSetting.CanParseToMuteType(value) == True:
            if value == MuteSetting.MuteType.VisualMute:
                ret = "VisualMute"
            elif value == MuteSetting.MuteType.AudioMute:
                ret = "AudioMute"
            elif value == MuteSetting.MuteType.AudioAndVisualMute:
                ret = "AudioAndVisualMute"
            else: # Don't come here
                ret = "Unknown"
        return ret

    def GetMuteValueString(value):
        ret = "Error"
        if MuteSetting.CanParseToMuteValue(value) == True:
            if value == MuteSetting.MuteValue.Off:
                ret = "Off"
            elif value == MuteSetting.MuteValue.On:
                ret = "On"
            else: # Don't come here
                ret = "Unknown"
        return ret


class CommandResult:

    # variables
    __sent_packet_list = []
    __received_packet_list = []
    __error_code = ErrorCode.UNKNOWN_ERROR
    __pjlink_responsecode = ResponseCode.Indefinite
    __pjlink_request_result_dict = {}

    def __init__(self):
        pass

    def __del__(self):
        pass

    def Init(self):
        self.__sent_packet_list.clear()
        self.__received_packet_list.clear()
        self.__error_code = ErrorCode.UNKNOWN_ERROR
        self.__pjlink_responsecode = ResponseCode.Indefinite
        self.__pjlink_request_result_dict.clear()

    def SetSentPacket(self, packet_list):
        self.__sent_packet_list.clear()
        self.__sent_packet_list.extend(packet_list)

    def SetReceivedPacket(self, packet_list):
        self.__received_packet_list.clear()
        self.__received_packet_list.extend(packet_list)

    def GetAndCopySentPacket(self):
        return copy.deepcopy(self.__sent_packet_list)

    def GetAndCopyReceivedPacket(self):
        return copy.deepcopy(self.__received_packet_list)

    def SetErrorCode(self, error_code):
        self.__error_code = error_code

    def GetErrorCode(self):
        return self.__error_code

    def SetPJLinkResponseCode(self, code):
        self.__pjlink_responsecode = code

    def GetPJLinkResponseCode(self):
        return self.__pjlink_responsecode

    def SetPJLinkRequestResult(self, key, value):
        self.__pjlink_request_result_dict[key] = value

    def ReplacePJLinkRequestResult(self, dict):
        self.__pjlink_request_result_dict = dict
    
    def GetPJLinkRequestResult(self):
        return self.__pjlink_request_result_dict


class CommandControl_Class1:

    # connection status
    __is_connected = False

    # common
    __connection_type = ConnectionType.UNKNOWN
    __timeout_sec = 3.0
    __send_receive_delay_sec = 0.1
    __send_retry_num = 0
    __receive_retry_num = 0
    __retry_delay_sec = 0.0

    # for TCP
    __tcp_ip_address_v4 = "192.168.0.100"
    __tcp_port = Const.DefaultTcpPort
    __sock = SocketCommTcpPy()

    # PJLink
    __pjlink_password = ""
    __pjlink_password_enabled = False
    __pjlink_crypted_digest_list = []


    def __impl_init(self):
        
        # common
        self.__is_connected = False
        self.__connection_type = ConnectionType.UNKNOWN
        self.__timeout_sec = 3.0
        self.__send_receive_delay_sec = 0.1
        self.__send_retry_num = 0
        self.__receive_retry_num = 0
        self.__retry_delay_sec = 0.0

        # TCP
        self.__tcp_ip_address_v4 = "192.168.0.100"
        self.__tcp_port = Const.DefaultTcpPort

        # PJLink
        self.__pjlink_password = ""
        self.__pjlink_password_enabled = False
        self.__pjlink_crypted_digest_list.clear()

        return None


    def __impl_finalize(self):
        self.__impl_disconnect()
        return None


    def __impl_connect(self):
        ret = False
        if self.__connection_type == ConnectionType.TCP:
            tcp_ok = self.__sock.OpenConnection(self.__tcp_ip_address_v4, self.__tcp_port, self.__timeout_sec)
            if tcp_ok == True:
                ret = True
        else: # Connection type Unknown
            ret = False

        self.__is_connected = ret
        return ret


    def __impl_authenticate(self):
        if self.__is_connected == False:
            return False

        # Get authentication result
        recv_packet_list = []
        if self.__impl_receive_packet_with_specific_timeout(recv_packet_list, self.__connection_type, 2.0) == False: # PJLink spec wait for 2.0 sec
            return False
        
        # Parse
        parse_ok = False
        recv_packet_size = len(recv_packet_list)
        if recv_packet_size == 18 or recv_packet_size == 19: # Some NEC Projectors add null character at the end of the packet
            # P J L I N K SP 1 SP [code] CR
            if recv_packet_list[0] == 0x50 \
              and recv_packet_list[1] == 0x4a \
              and recv_packet_list[2] == 0x4c \
              and recv_packet_list[3] == 0x49 \
              and recv_packet_list[4] == 0x4e \
              and recv_packet_list[5] == 0x4b \
              and recv_packet_list[6] == 0x20 \
              and recv_packet_list[7] == 0x31 \
              and recv_packet_list[8] == 0x20 \
              and recv_packet_list[17]== 0x0d:
                if self.__pjlink_password == "":
                    parse_ok = False
                else:
                    digest_str = ""
                    try:
                        digest_str += str((recv_packet_list[9]).to_bytes(1, 'little'), encoding='ascii', errors='strict')
                        digest_str += str((recv_packet_list[10]).to_bytes(1, 'little'), encoding='ascii', errors='strict')
                        digest_str += str((recv_packet_list[11]).to_bytes(1, 'little'), encoding='ascii', errors='strict')
                        digest_str += str((recv_packet_list[12]).to_bytes(1, 'little'), encoding='ascii', errors='strict')
                        digest_str += str((recv_packet_list[13]).to_bytes(1, 'little'), encoding='ascii', errors='strict')
                        digest_str += str((recv_packet_list[14]).to_bytes(1, 'little'), encoding='ascii', errors='strict')
                        digest_str += str((recv_packet_list[15]).to_bytes(1, 'little'), encoding='ascii', errors='strict')
                        digest_str += str((recv_packet_list[16]).to_bytes(1, 'little'), encoding='ascii', errors='strict')
                        digest_str += self.__pjlink_password
                        digest_byte = bytes(digest_str, encoding='ascii', errors='strict')
                        
                        crypted_str = hashlib.md5(digest_byte).hexdigest()
                        crypted_bytes = bytes(crypted_str, encoding='ascii', errors='strict')

                        # output
                        self.__pjlink_crypted_digest_list.clear()
                        for index in range(len(crypted_bytes)):
                            #print(crypted_bytes[index])
                            self.__pjlink_crypted_digest_list.append(crypted_bytes[index])
                        
                        self.__pjlink_password_enabled = True # Enable password
                        parse_ok = True

                    except Exception as e:
                        print(e)
                        parse_ok = False
                    
            else:
                parse_ok = False

        elif recv_packet_size == 9 or recv_packet_size == 10: # Some NEC Projectors add null character at the end of the packet
            # P J L I N K SP 0 CR
            if recv_packet_list[0] == 0x50 \
              and recv_packet_list[1] == 0x4a \
              and recv_packet_list[2] == 0x4c \
              and recv_packet_list[3] == 0x49 \
              and recv_packet_list[4] == 0x4e \
              and recv_packet_list[5] == 0x4b \
              and recv_packet_list[6] == 0x20 \
              and recv_packet_list[7] == 0x30 \
              and recv_packet_list[8] == 0x0d:
                parse_ok = True
            else:
                parse_ok = False
    
        else: # Error
            parse_ok = False

        return parse_ok


    def __impl_disconnect(self):
        #print("CommandControl: call disconnect")
        if self.__is_connected == True:
            if self.__connection_type == ConnectionType.TCP:
                self.__sock.CloseConnection()
            else:
                pass
        return None


    def __impl_send_packet(self, packet_list, connection_type):
        if len(packet_list) <= 0:
            return False

        sent_size = 0
        if connection_type == ConnectionType.TCP:
            sent_size = self.__sock.Send(packet_list, self.__timeout_sec)
        else:
            pass

        return True if sent_size > 0 else False


    def __impl_receive_packet(self, packet_list, connection_type):
        recv_size = 0
        if connection_type == ConnectionType.TCP:
            data = self.__sock.Receive(self.__timeout_sec)
            if data != None:
                recv_size = len(data)
                packet_list.extend(data)
        else:
            pass

        return True if recv_size > 0 else False


    def __impl_receive_packet_with_specific_timeout(self, packet_list, connection_type, timeout_sec):
        recv_size = 0
        if connection_type == ConnectionType.TCP:
            data = self.__sock.Receive(timeout_sec)
            if data != None:
                recv_size = len(data)
                packet_list.extend(data)
        else:
            pass

        return True if recv_size > 0 else False


    def __impl_send_receive_packet(self, send_packet_list, recv_packet_list, connection_type):

        ret = ErrorCode.UNKNOWN_ERROR
        for i in range(self.__send_retry_num + 1):        
            # send
            send_ok = self.__impl_send_packet(send_packet_list, connection_type)
            if send_ok == False:
                ret = ErrorCode.SEND_ERROR
                time.sleep(self.__retry_delay_sec)
                continue

            # delay
            time.sleep(self.__send_receive_delay_sec)

            # receive
            recv_ok = False
            for j in range(self.__receive_retry_num + 1):
                recv_ok = self.__impl_receive_packet(recv_packet_list, connection_type)
                if recv_ok == True:
                    break

            if recv_ok == True:
                ret = ErrorCode.NO_ERROR
                break
            else:
                ret = ErrorCode.RECV_ERROR
                time.sleep(self.__retry_delay_sec)
                # => retry from send

        # exit
        return ret


    def __init__(self):
        self.__impl_init()
        self.__is_connected = False
        self.__connection_type = ConnectionType.UNKNOWN
        return None


    def __del__(self):
        self.__impl_finalize()
        return None


    def __enter__(self):
        return self


    def __exit__(self, exc_type, exc_value, traceback):
        self.__impl_finalize()


    def GetCurrentConnectionType(self):
        return self.__connection_type


    def IsConnected(self):
        return self.__is_connected


    def ChangeSettings(self, timeout_sec = 3.0, send_recv_delay_sec=0.1, 
                    send_retry_num=0, recv_retry_num=0, retry_delay_sec=0.1):
        self.__timeout_sec = timeout_sec
        self.__send_receive_delay_sec = send_recv_delay_sec
        self.__send_retry_num = send_retry_num
        self.__receive_retry_num = recv_retry_num
        self.__retry_delay_sec = retry_delay_sec
        return None

    
    def Connect(self, tcp_ip_v4_str, pjlink_password_str="", tcp_port=Const.DefaultTcpPort, timeout_sec = 3.0, 
                send_recv_delay_sec=0.1, send_retry_num=0, recv_retry_num=0, retry_delay_sec=0.1):
        if self.__is_connected == True:
            return False # already connected

        self.__impl_init()
        self.__connection_type = ConnectionType.TCP
        self.__tcp_ip_address_v4 = tcp_ip_v4_str
        self.__tcp_port = tcp_port
        self.__timeout_sec = timeout_sec
        self.__send_receive_delay_sec = send_recv_delay_sec
        self.__send_retry_num = send_retry_num
        self.__receive_retry_num = recv_retry_num
        self.__retry_delay_sec = retry_delay_sec

        if pjlink_password_str == None:
            pjlink_password_str = ""
        if pjlink_password_str != "":
            pass # ToDo: check password character
        self.__pjlink_password = pjlink_password_str

        ret = False
        if self.__impl_connect() == True:
            if self.__impl_authenticate() == False:
                print("PJLink password is unmatch!!")
                self.__impl_disconnect() # Authentication failed and disconnect network
            else:
                ret = True
    
        return ret



    def Disconnect(self):
        return self.__impl_disconnect()



    ### SetPower
    def __setPower_CmdBody(self, connection_type, is_to_on):
        cmd_result = CommandResult()
        # % 1 P O W R SP [0 or 1] CR
        send_packet = array.array('B', [0x25, 0x31, 0x50, 0x4f, 0x57, 0x52, 0x20, 0x31, 0x0d])
        recv_packet = array.array('B', [])

        # make send packet
        send_packet[7] = 0x31 if is_to_on == True else 0x30

        # if the password is enabled, adding a digest code
        if self.__pjlink_password_enabled == True:
            send_packet_with_pass = array.array('B', [])
            for value in self.__pjlink_crypted_digest_list:
                send_packet_with_pass.append(value)
            send_packet_with_pass.extend(send_packet)
            send_packet = send_packet_with_pass

        # execute send and receive
        err_code = self.__impl_send_receive_packet(send_packet, recv_packet, connection_type)

        # check received packet
        pjlink_resp = ResponseCode.Indefinite
        if err_code == ErrorCode.NO_ERROR:

            if len(recv_packet) == 10: # OK?
                # % 1 P O W R = O K CR
                if  recv_packet[0] == 0x25 \
                and recv_packet[1] == 0x31 \
                and recv_packet[2] == 0x50 \
                and recv_packet[3] == 0x4f \
                and recv_packet[4] == 0x57 \
                and recv_packet[5] == 0x52 \
                and recv_packet[6] == 0x3d \
                and recv_packet[7] == 0x4f \
                and recv_packet[8] == 0x4b \
                and recv_packet[9] == 0x0d:
                    err_code = ErrorCode.NO_ERROR
                    pjlink_resp = ResponseCode.NoError
                else: # unknown packet
                    err_code = ErrorCode.RECV_INVALID_PACKET_ERROR

            elif len(recv_packet) == 12 and recv_packet[0] == 0x25: # Error?
                # % 1 P O W R = E R R X CR
                if  recv_packet[0] == 0x25 \
                and recv_packet[1] == 0x31 \
                and recv_packet[2] == 0x50 \
                and recv_packet[3] == 0x4f \
                and recv_packet[4] == 0x57 \
                and recv_packet[5] == 0x52 \
                and recv_packet[6] == 0x3d \
                and recv_packet[7] == 0x45 \
                and recv_packet[8] == 0x52 \
                and recv_packet[9] == 0x52 \
                and recv_packet[11] == 0x0d:
                    if recv_packet[10] == 0x32: # ERR2
                        err_code = ErrorCode.NO_ERROR
                        pjlink_resp = ResponseCode.ParameterIsRangeOver
                    elif recv_packet[10] == 0x33: # ERR3
                        err_code = ErrorCode.NO_ERROR
                        pjlink_resp = ResponseCode.UnacceptablePeriod
                    elif recv_packet[10] == 0x34: # ERR4
                        err_code = ErrorCode.NO_ERROR
                        pjlink_resp = ResponseCode.DisplayDeviceIsError
                    else: # unknown error
                        err_code = ErrorCode.RECV_INVALID_PACKET_ERROR

            elif len(recv_packet) == 12 and recv_packet[0] == 0x50: # Authentication error?
                # P J L I N K SP E R R A CR
                if  recv_packet[0] == 0x50 \
                and recv_packet[1] == 0x4a \
                and recv_packet[2] == 0x4c \
                and recv_packet[3] == 0x49 \
                and recv_packet[4] == 0x4e \
                and recv_packet[5] == 0x4b \
                and recv_packet[6] == 0x20 \
                and recv_packet[7] == 0x45 \
                and recv_packet[8] == 0x52 \
                and recv_packet[9] == 0x52 \
                and recv_packet[10]== 0x41 \
                and recv_packet[11]== 0x0d:
                    err_code = ErrorCode.NO_ERROR
                    pjlink_resp = ResponseCode.PasswordIsMismatch
                else: # unknown error
                        err_code = ErrorCode.RECV_INVALID_PACKET_ERROR
                    
            else: # packet length error
                err_code = ErrorCode.RECV_INVALID_PACKET_ERROR

        # set error_code
        cmd_result.SetErrorCode(err_code)
        cmd_result.SetPJLinkResponseCode(pjlink_resp)

        # set communication packets for debug and development
        if len(send_packet):
            cmd_result.SetSentPacket(send_packet)
        if len(recv_packet):
            cmd_result.SetReceivedPacket(recv_packet)

        return cmd_result


    def SetPower(self, is_to_on):
        ret = CommandResult()

        if self.__is_connected == False:
            ret.SetErrorCode(ErrorCode.CONNECTION_ERROR)
        else:
            if self.__connection_type == ConnectionType.TCP:
                ret = self.__setPower_CmdBody(self.__connection_type, is_to_on)
            else:
                ret.SetErrorCode(ErrorCode.CONNECTION_TYPE_ERROR)
        
        return ret


    ### GetPower
    def __getPower_CmdBody(self, connection_type):
        cmd_result = CommandResult()
        # % 1 P O W R SP ? CR
        send_packet = array.array('B', [0x25, 0x31, 0x50, 0x4f, 0x57, 0x52, 0x20, 0x3f, 0x0d])
        recv_packet = array.array('B', [])

        # if the password is enabled, adding a digest code
        if self.__pjlink_password_enabled == True:
            send_packet_with_pass = array.array('B', [])
            for value in self.__pjlink_crypted_digest_list:
                send_packet_with_pass.append(value)
            send_packet_with_pass.extend(send_packet)
            send_packet = send_packet_with_pass

        # execute send and receive
        err_code = self.__impl_send_receive_packet(send_packet, recv_packet, connection_type)

        # check received packet
        pjlink_resp = ResponseCode.Indefinite
        pjlink_request_result = {}
        if err_code == ErrorCode.NO_ERROR:

            if len(recv_packet) == 9: # OK?
                # % 1 P O W R = X CR
                if  recv_packet[0] == 0x25 \
                and recv_packet[1] == 0x31 \
                and recv_packet[2] == 0x50 \
                and recv_packet[3] == 0x4f \
                and recv_packet[4] == 0x57 \
                and recv_packet[5] == 0x52 \
                and recv_packet[6] == 0x3d \
                and recv_packet[8] == 0x0d:
                    if recv_packet[7] == 0x30: # Power off
                        err_code = ErrorCode.NO_ERROR
                        pjlink_resp = ResponseCode.NoError
                        pjlink_request_result["Power status"] = "Power off"
                    elif recv_packet[7] == 0x31: # Power on
                        err_code = ErrorCode.NO_ERROR
                        pjlink_resp = ResponseCode.NoError
                        pjlink_request_result["Power status"] = "Power on"
                    elif recv_packet[7] == 0x32: # Cooling
                        err_code = ErrorCode.NO_ERROR
                        pjlink_resp = ResponseCode.NoError
                        pjlink_request_result["Power status"] = "Cooling"
                    elif recv_packet[7] == 0x33: # Warmup
                        err_code = ErrorCode.NO_ERROR
                        pjlink_resp = ResponseCode.NoError
                        pjlink_request_result["Power status"] = "Warmup"
                    else:
                        err_code = ErrorCode.RECV_INVALID_PACKET_ERROR

                else: # unknown packet
                    err_code = ErrorCode.RECV_INVALID_PACKET_ERROR

            elif len(recv_packet) == 12 and recv_packet[0] == 0x25: # Error?
                # % 1 P O W R = E R R X CR
                if  recv_packet[0] == 0x25 \
                and recv_packet[1] == 0x31 \
                and recv_packet[2] == 0x50 \
                and recv_packet[3] == 0x4f \
                and recv_packet[4] == 0x57 \
                and recv_packet[5] == 0x52 \
                and recv_packet[6] == 0x3d \
                and recv_packet[7] == 0x45 \
                and recv_packet[8] == 0x52 \
                and recv_packet[9] == 0x52 \
                and recv_packet[11] == 0x0d:
                    if recv_packet[10] == 0x33: # ERR3
                        err_code = ErrorCode.NO_ERROR
                        pjlink_resp = ResponseCode.UnacceptablePeriod
                    elif recv_packet[10] == 0x34: # ERR4
                        err_code = ErrorCode.NO_ERROR
                        pjlink_resp = ResponseCode.DisplayDeviceIsError
                    else: # unknown error
                        err_code = ErrorCode.RECV_INVALID_PACKET_ERROR

            elif len(recv_packet) == 12 and recv_packet[0] == 0x50: # Authentication error?
                # P J L I N K SP E R R A CR
                if  recv_packet[0] == 0x50 \
                and recv_packet[1] == 0x4a \
                and recv_packet[2] == 0x4c \
                and recv_packet[3] == 0x49 \
                and recv_packet[4] == 0x4e \
                and recv_packet[5] == 0x4b \
                and recv_packet[6] == 0x20 \
                and recv_packet[7] == 0x45 \
                and recv_packet[8] == 0x52 \
                and recv_packet[9] == 0x52 \
                and recv_packet[10]== 0x41 \
                and recv_packet[11]== 0x0d:
                    err_code = ErrorCode.NO_ERROR
                    pjlink_resp = ResponseCode.PasswordIsMismatch
                else: # unknown error
                        err_code = ErrorCode.RECV_INVALID_PACKET_ERROR
                    
            else: # packet length error
                err_code = ErrorCode.RECV_INVALID_PACKET_ERROR

        # set error_code
        cmd_result.SetErrorCode(err_code)
        cmd_result.SetPJLinkResponseCode(pjlink_resp)
        cmd_result.ReplacePJLinkRequestResult(pjlink_request_result)

        # set communication packets for debug and development
        if len(send_packet):
            cmd_result.SetSentPacket(send_packet)
        if len(recv_packet):
            cmd_result.SetReceivedPacket(recv_packet)

        return cmd_result


    def GetPower(self):
        ret = CommandResult()

        if self.__is_connected == False:
            ret.SetErrorCode(ErrorCode.CONNECTION_ERROR)
        else:
            if self.__connection_type == ConnectionType.TCP:
                ret = self.__getPower_CmdBody(self.__connection_type)
            else:
                ret.SetErrorCode(ErrorCode.CONNECTION_TYPE_ERROR)
        
        return ret


    ### SetInput
    def __setInput_CmdBody(self, connection_type, pjlink_inputsource):
        cmd_result = CommandResult()
        # % 1 I N P T SP Type Value CR
        send_packet = array.array('B', [0x25, 0x31, 0x49, 0x4E, 0x50, 0x54, 0x20, 0x00, 0x00, 0x0d])
        recv_packet = array.array('B', [])

        # make send packet
        send_packet[7] = pjlink_inputsource.Type
        send_packet[8] = pjlink_inputsource.Number

        # if the password is enabled, adding a digest code
        if self.__pjlink_password_enabled == True:
            send_packet_with_pass = array.array('B', [])
            for value in self.__pjlink_crypted_digest_list:
                send_packet_with_pass.append(value)
            send_packet_with_pass.extend(send_packet)
            send_packet = send_packet_with_pass

        # execute send and receive
        err_code = self.__impl_send_receive_packet(send_packet, recv_packet, connection_type)

        # check received packet
        pjlink_resp = ResponseCode.Indefinite
        if err_code == ErrorCode.NO_ERROR:

            if len(recv_packet) == 10: # OK?
                # % 1 I N P T = O K CR
                if  recv_packet[0] == 0x25 \
                and recv_packet[1] == 0x31 \
                and recv_packet[2] == 0x49 \
                and recv_packet[3] == 0x4e \
                and recv_packet[4] == 0x50 \
                and recv_packet[5] == 0x54 \
                and recv_packet[6] == 0x3d \
                and recv_packet[7] == 0x4f \
                and recv_packet[8] == 0x4b \
                and recv_packet[9] == 0x0d:
                    err_code = ErrorCode.NO_ERROR
                    pjlink_resp = ResponseCode.NoError
                else: # unknown packet
                    err_code = ErrorCode.RECV_INVALID_PACKET_ERROR

            elif len(recv_packet) == 12 and recv_packet[0] == 0x25: # Error?
                # % 1 I N P T = E R R X CR
                if  recv_packet[0] == 0x25 \
                and recv_packet[1] == 0x31 \
                and recv_packet[2] == 0x49 \
                and recv_packet[3] == 0x4e \
                and recv_packet[4] == 0x50 \
                and recv_packet[5] == 0x54 \
                and recv_packet[6] == 0x3d \
                and recv_packet[7] == 0x45 \
                and recv_packet[8] == 0x52 \
                and recv_packet[9] == 0x52 \
                and recv_packet[11] == 0x0d:
                    if recv_packet[10] == 0x32: # ERR2
                        err_code = ErrorCode.NO_ERROR
                        pjlink_resp = ResponseCode.ParameterIsRangeOver
                    elif recv_packet[10] == 0x33: # ERR3
                        err_code = ErrorCode.NO_ERROR
                        pjlink_resp = ResponseCode.UnacceptablePeriod
                    elif recv_packet[10] == 0x34: # ERR4
                        err_code = ErrorCode.NO_ERROR
                        pjlink_resp = ResponseCode.DisplayDeviceIsError
                    else: # unknown error
                        err_code = ErrorCode.RECV_INVALID_PACKET_ERROR

            elif len(recv_packet) == 12 and recv_packet[0] == 0x50: # Authentication error?
                # P J L I N K SP E R R A CR
                if  recv_packet[0] == 0x50 \
                and recv_packet[1] == 0x4a \
                and recv_packet[2] == 0x4c \
                and recv_packet[3] == 0x49 \
                and recv_packet[4] == 0x4e \
                and recv_packet[5] == 0x4b \
                and recv_packet[6] == 0x20 \
                and recv_packet[7] == 0x45 \
                and recv_packet[8] == 0x52 \
                and recv_packet[9] == 0x52 \
                and recv_packet[10]== 0x41 \
                and recv_packet[11]== 0x0d:
                    err_code = ErrorCode.NO_ERROR
                    pjlink_resp = ResponseCode.PasswordIsMismatch
                else: # unknown error
                        err_code = ErrorCode.RECV_INVALID_PACKET_ERROR
                    
            else: # packet length error
                err_code = ErrorCode.RECV_INVALID_PACKET_ERROR

        # set error_code
        cmd_result.SetErrorCode(err_code)
        cmd_result.SetPJLinkResponseCode(pjlink_resp)

        # set communication packets for debug and development
        if len(send_packet):
            cmd_result.SetSentPacket(send_packet)
        if len(recv_packet):
            cmd_result.SetReceivedPacket(recv_packet)

        return cmd_result


    def SetInput(self, inputsource):
        ret = CommandResult()

        if self.__is_connected == False:
            ret.SetErrorCode(ErrorCode.CONNECTION_ERROR)
        else:
            if self.__connection_type == ConnectionType.TCP:
                ret = self.__setInput_CmdBody(self.__connection_type, inputsource)
            else:
                ret.SetErrorCode(ErrorCode.CONNECTION_TYPE_ERROR)
        
        return ret

    
    ### GetInput
    def __getInput_CmdBody(self, connection_type):
        cmd_result = CommandResult()
        # % 1 I N P T SP ? CR
        send_packet = array.array('B', [0x25, 0x31, 0x49, 0x4e, 0x50, 0x54, 0x20, 0x3f, 0x0d])
        recv_packet = array.array('B', [])

        # if the password is enabled, adding a digest code
        if self.__pjlink_password_enabled == True:
            send_packet_with_pass = array.array('B', [])
            for value in self.__pjlink_crypted_digest_list:
                send_packet_with_pass.append(value)
            send_packet_with_pass.extend(send_packet)
            send_packet = send_packet_with_pass

        # execute send and receive
        err_code = self.__impl_send_receive_packet(send_packet, recv_packet, connection_type)

        # check received packet
        pjlink_resp = ResponseCode.Indefinite
        pjlink_request_result = {}
        if err_code == ErrorCode.NO_ERROR:

            if len(recv_packet) == 10: # OK?
                # % 1 I N P T = X CR
                if  recv_packet[0] == 0x25 \
                and recv_packet[1] == 0x31 \
                and recv_packet[2] == 0x49 \
                and recv_packet[3] == 0x4e \
                and recv_packet[4] == 0x50 \
                and recv_packet[5] == 0x54 \
                and recv_packet[6] == 0x3d \
                and recv_packet[9] == 0x0d:
                    
                    if InputSource.CanParseToInputType(recv_packet[7]) \
                        and InputSource.CanParseToInputNumber(recv_packet[8]):
                            err_code = ErrorCode.NO_ERROR
                            pjlink_resp = ResponseCode.NoError
                            pjlink_request_result["InputType"] = InputSource.GetInputTypeString(recv_packet[7])
                            pjlink_request_result["InputNumber"] = InputSource.GetInputNumberString(recv_packet[8])
                    else:
                        # unknown input
                        err_code = ErrorCode.RECV_INVALID_PACKET_ERROR

                else: # unknown packet
                    err_code = ErrorCode.RECV_INVALID_PACKET_ERROR

            elif len(recv_packet) == 12 and recv_packet[0] == 0x25: # Error?
                # % 1 I N P T = E R R X CR
                if  recv_packet[0] == 0x25 \
                and recv_packet[1] == 0x31 \
                and recv_packet[2] == 0x49 \
                and recv_packet[3] == 0x4e \
                and recv_packet[4] == 0x50 \
                and recv_packet[5] == 0x54 \
                and recv_packet[6] == 0x3d \
                and recv_packet[7] == 0x45 \
                and recv_packet[8] == 0x52 \
                and recv_packet[9] == 0x52 \
                and recv_packet[11] == 0x0d:
                    if recv_packet[10] == 0x33: # ERR3
                        err_code = ErrorCode.NO_ERROR
                        pjlink_resp = ResponseCode.UnacceptablePeriod
                    elif recv_packet[10] == 0x34: # ERR4
                        err_code = ErrorCode.NO_ERROR
                        pjlink_resp = ResponseCode.DisplayDeviceIsError
                    else: # unknown error
                        err_code = ErrorCode.RECV_INVALID_PACKET_ERROR

            elif len(recv_packet) == 12 and recv_packet[0] == 0x50: # Authentication error?
                # P J L I N K SP E R R A CR
                if  recv_packet[0] == 0x50 \
                and recv_packet[1] == 0x4a \
                and recv_packet[2] == 0x4c \
                and recv_packet[3] == 0x49 \
                and recv_packet[4] == 0x4e \
                and recv_packet[5] == 0x4b \
                and recv_packet[6] == 0x20 \
                and recv_packet[7] == 0x45 \
                and recv_packet[8] == 0x52 \
                and recv_packet[9] == 0x52 \
                and recv_packet[10]== 0x41 \
                and recv_packet[11]== 0x0d:
                    err_code = ErrorCode.NO_ERROR
                    pjlink_resp = ResponseCode.PasswordIsMismatch
                else: # unknown error
                        err_code = ErrorCode.RECV_INVALID_PACKET_ERROR
                    
            else: # packet length error
                err_code = ErrorCode.RECV_INVALID_PACKET_ERROR

        # set error_code
        cmd_result.SetErrorCode(err_code)
        cmd_result.SetPJLinkResponseCode(pjlink_resp)
        cmd_result.ReplacePJLinkRequestResult(pjlink_request_result)

        # set communication packets for debug and development
        if len(send_packet):
            cmd_result.SetSentPacket(send_packet)
        if len(recv_packet):
            cmd_result.SetReceivedPacket(recv_packet)

        return cmd_result

    
    def GetInput(self):
        ret = CommandResult()

        if self.__is_connected == False:
            ret.SetErrorCode(ErrorCode.CONNECTION_ERROR)
        else:
            if self.__connection_type == ConnectionType.TCP:
                ret = self.__getInput_CmdBody(self.__connection_type)
            else:
                ret.SetErrorCode(ErrorCode.CONNECTION_TYPE_ERROR)
        
        return ret


    # set avmute
    def __setAVMute_CmdBody(self, connection_type, pjlink_mute_setting):
        cmd_result = CommandResult()
        # % 1 A V M T SP Type Value CR
        send_packet = array.array('B', [0x25, 0x31, 0x41, 0x56, 0x4d, 0x54, 0x20, 0x00, 0x00, 0x0d])
        recv_packet = array.array('B', [])

        # make send packet
        send_packet[7] = pjlink_mute_setting.Type
        send_packet[8] = pjlink_mute_setting.Value

        # if the password is enabled, adding a digest code
        if self.__pjlink_password_enabled == True:
            send_packet_with_pass = array.array('B', [])
            for value in self.__pjlink_crypted_digest_list:
                send_packet_with_pass.append(value)
            send_packet_with_pass.extend(send_packet)
            send_packet = send_packet_with_pass

        # execute send and receive
        err_code = self.__impl_send_receive_packet(send_packet, recv_packet, connection_type)

        # check received packet
        pjlink_resp = ResponseCode.Indefinite
        if err_code == ErrorCode.NO_ERROR:

            if len(recv_packet) == 10: # OK?
                # % 1 A V M T = O K CR
                if  recv_packet[0] == 0x25 \
                and recv_packet[1] == 0x31 \
                and recv_packet[2] == 0x41 \
                and recv_packet[3] == 0x56 \
                and recv_packet[4] == 0x4d \
                and recv_packet[5] == 0x54 \
                and recv_packet[6] == 0x3d \
                and recv_packet[7] == 0x4f \
                and recv_packet[8] == 0x4b \
                and recv_packet[9] == 0x0d:
                    err_code = ErrorCode.NO_ERROR
                    pjlink_resp = ResponseCode.NoError
                else: # unknown packet
                    err_code = ErrorCode.RECV_INVALID_PACKET_ERROR

            elif len(recv_packet) == 12 and recv_packet[0] == 0x25: # Error?
                # % 1 A V M T = E R R X CR
                if  recv_packet[0] == 0x25 \
                and recv_packet[1] == 0x31 \
                and recv_packet[2] == 0x41 \
                and recv_packet[3] == 0x56 \
                and recv_packet[4] == 0x4d \
                and recv_packet[5] == 0x54 \
                and recv_packet[6] == 0x3d \
                and recv_packet[7] == 0x45 \
                and recv_packet[8] == 0x52 \
                and recv_packet[9] == 0x52 \
                and recv_packet[11] == 0x0d:
                    if recv_packet[10] == 0x32: # ERR2
                        err_code = ErrorCode.NO_ERROR
                        pjlink_resp = ResponseCode.ParameterIsRangeOver
                    elif recv_packet[10] == 0x33: # ERR3
                        err_code = ErrorCode.NO_ERROR
                        pjlink_resp = ResponseCode.UnacceptablePeriod
                    elif recv_packet[10] == 0x34: # ERR4
                        err_code = ErrorCode.NO_ERROR
                        pjlink_resp = ResponseCode.DisplayDeviceIsError
                    else: # unknown error
                        err_code = ErrorCode.RECV_INVALID_PACKET_ERROR

            elif len(recv_packet) == 12 and recv_packet[0] == 0x50: # Authentication error?
                # P J L I N K SP E R R A CR
                if  recv_packet[0] == 0x50 \
                and recv_packet[1] == 0x4a \
                and recv_packet[2] == 0x4c \
                and recv_packet[3] == 0x49 \
                and recv_packet[4] == 0x4e \
                and recv_packet[5] == 0x4b \
                and recv_packet[6] == 0x20 \
                and recv_packet[7] == 0x45 \
                and recv_packet[8] == 0x52 \
                and recv_packet[9] == 0x52 \
                and recv_packet[10]== 0x41 \
                and recv_packet[11]== 0x0d:
                    err_code = ErrorCode.NO_ERROR
                    pjlink_resp = ResponseCode.PasswordIsMismatch
                else: # unknown error
                        err_code = ErrorCode.RECV_INVALID_PACKET_ERROR
                    
            else: # packet length error
                err_code = ErrorCode.RECV_INVALID_PACKET_ERROR

        # set error_code
        cmd_result.SetErrorCode(err_code)
        cmd_result.SetPJLinkResponseCode(pjlink_resp)

        # set communication packets for debug and development
        if len(send_packet):
            cmd_result.SetSentPacket(send_packet)
        if len(recv_packet):
            cmd_result.SetReceivedPacket(recv_packet)

        return cmd_result


    def SetAVMute(self, pjlink_mute_setting):
        ret = CommandResult()

        if self.__is_connected == False:
            ret.SetErrorCode(ErrorCode.CONNECTION_ERROR)
        else:
            if self.__connection_type == ConnectionType.TCP:
                ret = self.__setAVMute_CmdBody(self.__connection_type, pjlink_mute_setting)
            else:
                ret.SetErrorCode(ErrorCode.CONNECTION_TYPE_ERROR)
        
        return ret


    ### get avmute
    def __getAVMute_CmdBody(self, connection_type):
        cmd_result = CommandResult()
        # % 1 A V M T SP ? CR
        send_packet = array.array('B', [0x25, 0x31, 0x41, 0x56, 0x4d, 0x54, 0x20, 0x3f, 0x0d])
        recv_packet = array.array('B', [])

        # if the password is enabled, adding a digest code
        if self.__pjlink_password_enabled == True:
            send_packet_with_pass = array.array('B', [])
            for value in self.__pjlink_crypted_digest_list:
                send_packet_with_pass.append(value)
            send_packet_with_pass.extend(send_packet)
            send_packet = send_packet_with_pass

        # execute send and receive
        err_code = self.__impl_send_receive_packet(send_packet, recv_packet, connection_type)

        # check received packet
        pjlink_resp = ResponseCode.Indefinite
        pjlink_request_result = {}
        if err_code == ErrorCode.NO_ERROR:

            if len(recv_packet) == 10: # OK?
                # % 1 A V M T = X X CR
                if  recv_packet[0] == 0x25 \
                and recv_packet[1] == 0x31 \
                and recv_packet[2] == 0x41 \
                and recv_packet[3] == 0x56 \
                and recv_packet[4] == 0x4d \
                and recv_packet[5] == 0x54 \
                and recv_packet[6] == 0x3d \
                and recv_packet[9] == 0x0d:
                    if MuteSetting.CanParseToMuteType(recv_packet[7]) \
                        and MuteSetting.CanParseToMuteValue(recv_packet[8]):
                            err_code = ErrorCode.NO_ERROR
                            pjlink_resp = ResponseCode.NoError
                            pjlink_request_result["MuteType"] = MuteSetting.GetMuteTypeString(recv_packet[7])
                            pjlink_request_result["MuteValue"]= MuteSetting.GetMuteValueString(recv_packet[8])
                    else:
                        # unknown mute settings
                        err_code = ErrorCode.RECV_INVALID_PACKET_ERROR

                else: # unknown packet
                    err_code = ErrorCode.RECV_INVALID_PACKET_ERROR

            elif len(recv_packet) == 12 and recv_packet[0] == 0x25: # Error?
                # % 1 A V M T = E R R X CR
                if  recv_packet[0] == 0x25 \
                and recv_packet[1] == 0x31 \
                and recv_packet[2] == 0x41 \
                and recv_packet[3] == 0x56 \
                and recv_packet[4] == 0x4d \
                and recv_packet[5] == 0x54 \
                and recv_packet[6] == 0x3d \
                and recv_packet[7] == 0x45 \
                and recv_packet[8] == 0x52 \
                and recv_packet[9] == 0x52 \
                and recv_packet[11] == 0x0d:
                    if recv_packet[10] == 0x33: # ERR3
                        err_code = ErrorCode.NO_ERROR
                        pjlink_resp = ResponseCode.UnacceptablePeriod
                    elif recv_packet[10] == 0x34: # ERR4
                        err_code = ErrorCode.NO_ERROR
                        pjlink_resp = ResponseCode.DisplayDeviceIsError
                    else: # unknown error
                        err_code = ErrorCode.RECV_INVALID_PACKET_ERROR

            elif len(recv_packet) == 12 and recv_packet[0] == 0x50: # Authentication error?
                # P J L I N K SP E R R A CR
                if  recv_packet[0] == 0x50 \
                and recv_packet[1] == 0x4a \
                and recv_packet[2] == 0x4c \
                and recv_packet[3] == 0x49 \
                and recv_packet[4] == 0x4e \
                and recv_packet[5] == 0x4b \
                and recv_packet[6] == 0x20 \
                and recv_packet[7] == 0x45 \
                and recv_packet[8] == 0x52 \
                and recv_packet[9] == 0x52 \
                and recv_packet[10]== 0x41 \
                and recv_packet[11]== 0x0d:
                    err_code = ErrorCode.NO_ERROR
                    pjlink_resp = ResponseCode.PasswordIsMismatch
                else: # unknown error
                        err_code = ErrorCode.RECV_INVALID_PACKET_ERROR
                    
            else: # packet length error
                err_code = ErrorCode.RECV_INVALID_PACKET_ERROR

        # set error_code
        cmd_result.SetErrorCode(err_code)
        cmd_result.SetPJLinkResponseCode(pjlink_resp)
        cmd_result.ReplacePJLinkRequestResult(pjlink_request_result)

        # set communication packets for debug and development
        if len(send_packet):
            cmd_result.SetSentPacket(send_packet)
        if len(recv_packet):
            cmd_result.SetReceivedPacket(recv_packet)

        return cmd_result

    
    def GetAVMute(self):
        ret = CommandResult()

        if self.__is_connected == False:
            ret.SetErrorCode(ErrorCode.CONNECTION_ERROR)
        else:
            if self.__connection_type == ConnectionType.TCP:
                ret = self.__getAVMute_CmdBody(self.__connection_type)
            else:
                ret.SetErrorCode(ErrorCode.CONNECTION_TYPE_ERROR)
        
        return ret


    ### get error status
    def __retErrorStatusString(self, value):
        if value == 0x30:
            return "No error or unsupported"
        elif value == 0x31:
            return "Warning"
        else: # maybe 0x32
            return "Error"


    def __getErrorStatus_CmdBody(self, connection_type):
        cmd_result = CommandResult()
        # % 1 E R S T SP ? CR
        send_packet = array.array('B', [0x25, 0x31, 0x45, 0x52, 0x53, 0x54, 0x20, 0x3f, 0x0d])
        recv_packet = array.array('B', [])

        # if the password is enabled, adding a digest code
        if self.__pjlink_password_enabled == True:
            send_packet_with_pass = array.array('B', [])
            for value in self.__pjlink_crypted_digest_list:
                send_packet_with_pass.append(value)
            send_packet_with_pass.extend(send_packet)
            send_packet = send_packet_with_pass

        # execute send and receive
        err_code = self.__impl_send_receive_packet(send_packet, recv_packet, connection_type)

        # check received packet
        pjlink_resp = ResponseCode.Indefinite
        pjlink_request_result = {}
        if err_code == ErrorCode.NO_ERROR:

            if len(recv_packet) == 14: # OK?
                # % 1 E R S T = XXXXXX CR
                if  recv_packet[0] == 0x25 \
                and recv_packet[1] == 0x31 \
                and recv_packet[2] == 0x45 \
                and recv_packet[3] == 0x52 \
                and recv_packet[4] == 0x53 \
                and recv_packet[5] == 0x54 \
                and recv_packet[6] == 0x3d \
                and recv_packet[13]== 0x0d:
                    if  (recv_packet[7] == 0x30 or recv_packet[7] == 0x31 or recv_packet[7] == 0x32) \
                    and (recv_packet[8] == 0x30 or recv_packet[8] == 0x31 or recv_packet[8] == 0x32) \
                    and (recv_packet[9] == 0x30 or recv_packet[9] == 0x31 or recv_packet[9] == 0x32) \
                    and (recv_packet[10] == 0x30 or recv_packet[10] == 0x31 or recv_packet[10] == 0x32) \
                    and (recv_packet[11] == 0x30 or recv_packet[11] == 0x31 or recv_packet[11] == 0x32) \
                    and (recv_packet[12] == 0x30 or recv_packet[12] == 0x31 or recv_packet[12] == 0x32):
                            err_code = ErrorCode.NO_ERROR
                            pjlink_resp = ResponseCode.NoError
                            pjlink_request_result["Status Fan"] = self.__retErrorStatusString(recv_packet[7])
                            pjlink_request_result["Status Lamp"] = self.__retErrorStatusString(recv_packet[8])
                            pjlink_request_result["Status Temperature"] = self.__retErrorStatusString(recv_packet[9])
                            pjlink_request_result["Status CoverOpen"] = self.__retErrorStatusString(recv_packet[10])
                            pjlink_request_result["Status Filter"] = self.__retErrorStatusString(recv_packet[11])
                            pjlink_request_result["Status Other"] = self.__retErrorStatusString(recv_packet[12])
                    else:
                        # unknown
                        err_code = ErrorCode.RECV_INVALID_PACKET_ERROR

                else: # unknown packet
                    err_code = ErrorCode.RECV_INVALID_PACKET_ERROR

            elif len(recv_packet) == 12 and recv_packet[0] == 0x25: # Error?
                # % 1 E R S T = E R R X CR
                if  recv_packet[0] == 0x25 \
                and recv_packet[1] == 0x31 \
                and recv_packet[2] == 0x45 \
                and recv_packet[3] == 0x52 \
                and recv_packet[4] == 0x53 \
                and recv_packet[5] == 0x54 \
                and recv_packet[6] == 0x3d \
                and recv_packet[7] == 0x45 \
                and recv_packet[8] == 0x52 \
                and recv_packet[9] == 0x52 \
                and recv_packet[11] == 0x0d:
                    if recv_packet[10] == 0x33: # ERR3
                        err_code = ErrorCode.NO_ERROR
                        pjlink_resp = ResponseCode.UnacceptablePeriod
                    elif recv_packet[10] == 0x34: # ERR4
                        err_code = ErrorCode.NO_ERROR
                        pjlink_resp = ResponseCode.DisplayDeviceIsError
                    else: # unknown error
                        err_code = ErrorCode.RECV_INVALID_PACKET_ERROR

            elif len(recv_packet) == 12 and recv_packet[0] == 0x50: # Authentication error?
                # P J L I N K SP E R R A CR
                if  recv_packet[0] == 0x50 \
                and recv_packet[1] == 0x4a \
                and recv_packet[2] == 0x4c \
                and recv_packet[3] == 0x49 \
                and recv_packet[4] == 0x4e \
                and recv_packet[5] == 0x4b \
                and recv_packet[6] == 0x20 \
                and recv_packet[7] == 0x45 \
                and recv_packet[8] == 0x52 \
                and recv_packet[9] == 0x52 \
                and recv_packet[10]== 0x41 \
                and recv_packet[11]== 0x0d:
                    err_code = ErrorCode.NO_ERROR
                    pjlink_resp = ResponseCode.PasswordIsMismatch
                else: # unknown error
                        err_code = ErrorCode.RECV_INVALID_PACKET_ERROR
                    
            else: # packet length error
                err_code = ErrorCode.RECV_INVALID_PACKET_ERROR

        # set error_code
        cmd_result.SetErrorCode(err_code)
        cmd_result.SetPJLinkResponseCode(pjlink_resp)
        cmd_result.ReplacePJLinkRequestResult(pjlink_request_result)

        # set communication packets for debug and development
        if len(send_packet):
            cmd_result.SetSentPacket(send_packet)
        if len(recv_packet):
            cmd_result.SetReceivedPacket(recv_packet)

        return cmd_result


    def GetErrorStatus(self):
        ret = CommandResult()
        if self.__is_connected == False:
            ret.SetErrorCode(ErrorCode.CONNECTION_ERROR)
        else:
            if self.__connection_type == ConnectionType.TCP:
                ret = self.__getErrorStatus_CmdBody(self.__connection_type)
            else:
                ret.SetErrorCode(ErrorCode.CONNECTION_TYPE_ERROR)
        return ret


    ### get lamp num and usage
    #__MAX_LAMP_NUM = 8
    __MAX_LAMP_USAGE_DIGIT = 5

    def __isAsciiNumericValue0to9(self, value):
        if value == 0x30 or value == 0x31 or value == 0x32 or value == 0x33 \
        or value == 0x34 or value == 0x35 or value == 0x36 or value == 0x37 \
        or value == 0x38 or value == 0x39:
            return True
        else:
            return False
        
    def __ConvertAsciiNumericCharaToValue(self, value):
        if value == 0x30: return 0
        elif value == 0x31: return 1
        elif value == 0x32: return 2
        elif value == 0x33: return 3
        elif value == 0x34: return 4
        elif value == 0x35: return 5
        elif value == 0x36: return 6
        elif value == 0x37: return 7
        elif value == 0x38: return 8
        elif value == 0x38: return 9
        else: return 0

    def __getLampNumAndUsageTime_CmdBody(self, connection_type):
        cmd_result = CommandResult()
        # % 1 L A M P SP ? CR
        send_packet = array.array('B', [0x25, 0x31, 0x4c, 0x41, 0x4d, 0x50, 0x20, 0x3f, 0x0d])
        recv_packet = array.array('B', [])

        # if the password is enabled, adding a digest code
        if self.__pjlink_password_enabled == True:
            send_packet_with_pass = array.array('B', [])
            for value in self.__pjlink_crypted_digest_list:
                send_packet_with_pass.append(value)
            send_packet_with_pass.extend(send_packet)
            send_packet = send_packet_with_pass

        # execute send and receive
        err_code = self.__impl_send_receive_packet(send_packet, recv_packet, connection_type)

        # check received packet
        pjlink_resp = ResponseCode.Indefinite
        pjlink_request_result = {}
        if err_code == ErrorCode.NO_ERROR:

            if len(recv_packet) == 12 and recv_packet[0] == 0x25: # Error?
                # % 1 L A M P = E R R X CR
                if  recv_packet[0] == 0x25 \
                and recv_packet[1] == 0x31 \
                and recv_packet[2] == 0x4c \
                and recv_packet[3] == 0x41 \
                and recv_packet[4] == 0x4d \
                and recv_packet[5] == 0x50 \
                and recv_packet[6] == 0x3d \
                and recv_packet[7] == 0x45 \
                and recv_packet[8] == 0x52 \
                and recv_packet[9] == 0x52 \
                and recv_packet[11] == 0x0d:
                    if recv_packet[10] == 0x31: # ERR1
                        err_code = ErrorCode.NO_ERROR
                        pjlink_resp = ResponseCode.NotHaveLamp
                    elif recv_packet[10] == 0x33: # ERR3
                        err_code = ErrorCode.NO_ERROR
                        pjlink_resp = ResponseCode.UnacceptablePeriod
                    elif recv_packet[10] == 0x34: # ERR4
                        err_code = ErrorCode.NO_ERROR
                        pjlink_resp = ResponseCode.DisplayDeviceIsError
                    else: # unknown error
                        err_code = ErrorCode.RECV_INVALID_PACKET_ERROR

            elif len(recv_packet) == 12 and recv_packet[0] == 0x50: # Authentication error?
                # P J L I N K SP E R R A CR
                if  recv_packet[0] == 0x50 \
                and recv_packet[1] == 0x4a \
                and recv_packet[2] == 0x4c \
                and recv_packet[3] == 0x49 \
                and recv_packet[4] == 0x4e \
                and recv_packet[5] == 0x4b \
                and recv_packet[6] == 0x20 \
                and recv_packet[7] == 0x45 \
                and recv_packet[8] == 0x52 \
                and recv_packet[9] == 0x52 \
                and recv_packet[10]== 0x41 \
                and recv_packet[11]== 0x0d:
                    err_code = ErrorCode.NO_ERROR
                    pjlink_resp = ResponseCode.PasswordIsMismatch
                else: # unknown error
                        err_code = ErrorCode.RECV_INVALID_PACKET_ERROR

            elif len(recv_packet) >= 11 and recv_packet[(len(recv_packet)-1)] == 0x0d: # OK? check minimum len and terminating
                # check header  % L A M P =
                if  recv_packet[0] == 0x25 \
                and recv_packet[1] == 0x31 \
                and recv_packet[2] == 0x4c \
                and recv_packet[3] == 0x41 \
                and recv_packet[4] == 0x4d \
                and recv_packet[5] == 0x50 \
                and recv_packet[6] == 0x3d:
                    invalid_flag = False

                    # parse packet
                    lamp_usages = []
                    lamp_statuses = []
                    pos = 7
                    while True:
                        if invalid_flag == True:
                            break

                        # lamp usage
                        tmp_usage = []
                        for cnt in range(self.__MAX_LAMP_USAGE_DIGIT):
                            if pos > (len(recv_packet) - 1):
                                invalid_flag = True
                                break

                            if recv_packet[pos] == 0x20:
                                break
                            else:
                                if self.__isAsciiNumericValue0to9(recv_packet[pos]):
                                    tmp_usage.append(self.__ConvertAsciiNumericCharaToValue(recv_packet[pos]))
                                else:
                                    invalid_flag = True
                                    break

                            # next
                            pos+=1

                        if len(tmp_usage) == 0:
                            invalid_flag = True
                        if invalid_flag == True:
                            continue

                        # lamp status
                        pos+=1
                        if pos > (len(recv_packet) - 1):
                            invalid_flag = True
                            continue
                        tmp_lamp_sts = "Error"
                        if recv_packet[pos] == 0x30: # '0'
                            tmp_lamp_sts = "LAMP OFF"
                        elif recv_packet[pos] == 0x31: # '1'
                            tmp_lamp_sts = "LAMP ON"
                        else:
                            invalid_flag = True
                            continue

                        # check space or terminated
                        pos+=1
                        if pos > (len(recv_packet) - 1):
                            invalid_flag = True
                            continue
                        if recv_packet[pos] != 0x20 and recv_packet[pos] != 0x0d:
                            invalid_flag = True
                            continue

                        # If it reached here, the data format is maybe ok
                        tmp_str = ""
                        for v in tmp_usage:
                            tmp_str += str(v)
                        lamp_statuses.append(tmp_lamp_sts)
                        lamp_usages.append(int(tmp_str))

                        # exit or next
                        if recv_packet[pos] == 0x0d: # exit
                            break
                        else: #next
                            pos+=1
                            if pos > (len(recv_packet) - 1):
                                invalid_flag = True
                    # while loop end

                    # result
                    if invalid_flag == True:
                        err_code = ErrorCode.RECV_INVALID_PACKET_ERROR
                    elif len(lamp_usages) != len(lamp_statuses):
                        err_code = ErrorCode.RECV_INVALID_PACKET_ERROR
                    else:
                        err_code = ErrorCode.NO_ERROR
                        pjlink_resp = ResponseCode.NoError
                        for i in range(len(lamp_usages)):
                            tmp_str1 = "LAMP No." + str(i+1)
                            tmp_str2 = "Status: " + lamp_statuses[i] + ", " + "Usage time: " + str(lamp_usages[i]) + " hours"
                            pjlink_request_result[tmp_str1] = tmp_str2

            else: # packet length error
                err_code = ErrorCode.RECV_INVALID_PACKET_ERROR

        # set error_code
        cmd_result.SetErrorCode(err_code)
        cmd_result.SetPJLinkResponseCode(pjlink_resp)
        cmd_result.ReplacePJLinkRequestResult(pjlink_request_result)

        # set communication packets for debug and development
        if len(send_packet):
            cmd_result.SetSentPacket(send_packet)
        if len(recv_packet):
            cmd_result.SetReceivedPacket(recv_packet)

        return cmd_result


    def GetLampNumAndUsageTime(self):
        ret = CommandResult()
        if self.__is_connected == False:
            ret.SetErrorCode(ErrorCode.CONNECTION_ERROR)
        else:
            if self.__connection_type == ConnectionType.TCP:
                ret = self.__getLampNumAndUsageTime_CmdBody(self.__connection_type)
            else:
                ret.SetErrorCode(ErrorCode.CONNECTION_TYPE_ERROR)
        return ret

    
    ### get input toggling list
    __INPUT_TOGGLING_LIST_DIGIT = 2
    def __getInputTogglingList_CmdBody(self, connection_type):
        cmd_result = CommandResult()
        # % 1 I N S T SP ? CR
        send_packet = array.array('B', [0x25, 0x31, 0x49, 0x4e, 0x53, 0x54, 0x20, 0x3f, 0x0d])
        recv_packet = array.array('B', [])

        # if the password is enabled, adding a digest code
        if self.__pjlink_password_enabled == True:
            send_packet_with_pass = array.array('B', [])
            for value in self.__pjlink_crypted_digest_list:
                send_packet_with_pass.append(value)
            send_packet_with_pass.extend(send_packet)
            send_packet = send_packet_with_pass

        # execute send and receive
        err_code = self.__impl_send_receive_packet(send_packet, recv_packet, connection_type)

        # check received packet
        pjlink_resp = ResponseCode.Indefinite
        pjlink_request_result = {}
        if err_code == ErrorCode.NO_ERROR:

            if len(recv_packet) == 12 and recv_packet[0] == 0x25: # Error?
                # % 1 I N S T = E R R X CR
                if  recv_packet[0] == 0x25 \
                and recv_packet[1] == 0x31 \
                and recv_packet[2] == 0x49 \
                and recv_packet[3] == 0x4e \
                and recv_packet[4] == 0x53 \
                and recv_packet[5] == 0x54 \
                and recv_packet[6] == 0x3d \
                and recv_packet[7] == 0x45 \
                and recv_packet[8] == 0x52 \
                and recv_packet[9] == 0x52 \
                and recv_packet[11] == 0x0d:
                    if recv_packet[10] == 0x33: # ERR3
                        err_code = ErrorCode.NO_ERROR
                        pjlink_resp = ResponseCode.UnacceptablePeriod
                    elif recv_packet[10] == 0x34: # ERR4
                        err_code = ErrorCode.NO_ERROR
                        pjlink_resp = ResponseCode.DisplayDeviceIsError
                    else: # unknown error
                        err_code = ErrorCode.RECV_INVALID_PACKET_ERROR

            elif len(recv_packet) == 12 and recv_packet[0] == 0x50: # Authentication error?
                # P J L I N K SP E R R A CR
                if  recv_packet[0] == 0x50 \
                and recv_packet[1] == 0x4a \
                and recv_packet[2] == 0x4c \
                and recv_packet[3] == 0x49 \
                and recv_packet[4] == 0x4e \
                and recv_packet[5] == 0x4b \
                and recv_packet[6] == 0x20 \
                and recv_packet[7] == 0x45 \
                and recv_packet[8] == 0x52 \
                and recv_packet[9] == 0x52 \
                and recv_packet[10]== 0x41 \
                and recv_packet[11]== 0x0d:
                    err_code = ErrorCode.NO_ERROR
                    pjlink_resp = ResponseCode.PasswordIsMismatch
                else: # unknown error
                        err_code = ErrorCode.RECV_INVALID_PACKET_ERROR

            elif len(recv_packet) >= 10 and recv_packet[(len(recv_packet)-1)] == 0x0d: # OK? check minimum len and terminating
                # check header  % I N S T =
                if  recv_packet[0] == 0x25 \
                and recv_packet[1] == 0x31 \
                and recv_packet[2] == 0x49 \
                and recv_packet[3] == 0x4e \
                and recv_packet[4] == 0x53 \
                and recv_packet[5] == 0x54 \
                and recv_packet[6] == 0x3d:
                    invalid_flag = False

                    # parse packet
                    input_number_list = []
                    pos = 7
                    while True:
                        if invalid_flag == True:
                            break

                        # input number
                        tmp_input_number = []
                        for cnt in range(self.__INPUT_TOGGLING_LIST_DIGIT):
                            if pos > (len(recv_packet) - 1):
                                invalid_flag = True
                                break

                            if recv_packet[pos] == 0x20 or recv_packet[pos] == 0x0d:
                                break
                            else:
                                if self.__isAsciiNumericValue0to9(recv_packet[pos]):
                                    tmp_input_number.append(self.__ConvertAsciiNumericCharaToValue(recv_packet[pos]))
                                else:
                                    invalid_flag = True
                                    break

                            # next
                            pos+=1
                        if len(tmp_input_number) == 0:
                            invalid_flag = True
                        if invalid_flag == True:
                            continue

                        # If it reached here, the data format is maybe ok
                        tmp_str = ""
                        for v in tmp_input_number:
                            tmp_str += str(v)
                        input_number_list.append(int(tmp_str))

                        # exit or next
                        if recv_packet[pos] == 0x0d: # exit
                            break
                        elif recv_packet[pos] == 0x20: # next
                            pos+=1
                            if pos > (len(recv_packet) - 1):
                                invalid_flag = True
                        else: 
                            invalid_flag = True
                    # while loop end

                    # result
                    if invalid_flag == True:
                        err_code = ErrorCode.RECV_INVALID_PACKET_ERROR
                    else:
                        err_code = ErrorCode.NO_ERROR
                        pjlink_resp = ResponseCode.NoError
                        for i in range(len(input_number_list)):
                            tmp_str1 = "Input No." + str(i+1)
                            tmp_str2 = str(input_number_list[i])
                            pjlink_request_result[tmp_str1] = tmp_str2

            else: # packet length error
                err_code = ErrorCode.RECV_INVALID_PACKET_ERROR

        # set error_code
        cmd_result.SetErrorCode(err_code)
        cmd_result.SetPJLinkResponseCode(pjlink_resp)
        cmd_result.ReplacePJLinkRequestResult(pjlink_request_result)

        # set communication packets for debug and development
        if len(send_packet):
            cmd_result.SetSentPacket(send_packet)
        if len(recv_packet):
            cmd_result.SetReceivedPacket(recv_packet)

        return cmd_result


    def GetInputTogglingList(self):
        ret = CommandResult()
        if self.__is_connected == False:
            ret.SetErrorCode(ErrorCode.CONNECTION_ERROR)
        else:
            if self.__connection_type == ConnectionType.TCP:
                ret = self.__getInputTogglingList_CmdBody(self.__connection_type)
            else:
                ret.SetErrorCode(ErrorCode.CONNECTION_TYPE_ERROR)
        return ret
    

    ### get projector name
    __MAX_PJ_NAME_LEN = 64
    def __getProjectorName_CmdBody(self, connection_type):
        cmd_result = CommandResult()
        # % 1 N A M E SP ? CR
        send_packet = array.array('B', [0x25, 0x31, 0x4e, 0x41, 0x4d, 0x45, 0x20, 0x3f, 0x0d])
        recv_packet = array.array('B', [])

        # if the password is enabled, adding a digest code
        if self.__pjlink_password_enabled == True:
            send_packet_with_pass = array.array('B', [])
            for value in self.__pjlink_crypted_digest_list:
                send_packet_with_pass.append(value)
            send_packet_with_pass.extend(send_packet)
            send_packet = send_packet_with_pass

        # execute send and receive
        err_code = self.__impl_send_receive_packet(send_packet, recv_packet, connection_type)

        # check received packet
        pjlink_resp = ResponseCode.Indefinite
        pjlink_request_result = {}
        if err_code == ErrorCode.NO_ERROR:

            if len(recv_packet) == 12 and recv_packet[0] == 0x25: # Error?
                # % 1 N A M E = E R R X CR
                if  recv_packet[0] == 0x25 \
                and recv_packet[1] == 0x31 \
                and recv_packet[2] == 0x4e \
                and recv_packet[3] == 0x41 \
                and recv_packet[4] == 0x4d \
                and recv_packet[5] == 0x45 \
                and recv_packet[6] == 0x3d \
                and recv_packet[7] == 0x45 \
                and recv_packet[8] == 0x52 \
                and recv_packet[9] == 0x52 \
                and recv_packet[11] == 0x0d:
                    if recv_packet[10] == 0x33: # ERR3
                        err_code = ErrorCode.NO_ERROR
                        pjlink_resp = ResponseCode.UnacceptablePeriod
                    elif recv_packet[10] == 0x34: # ERR4
                        err_code = ErrorCode.NO_ERROR
                        pjlink_resp = ResponseCode.DisplayDeviceIsError
                    else: # unknown error
                        err_code = ErrorCode.RECV_INVALID_PACKET_ERROR

            elif len(recv_packet) == 12 and recv_packet[0] == 0x50: # Authentication error?
                # P J L I N K SP E R R A CR
                if  recv_packet[0] == 0x50 \
                and recv_packet[1] == 0x4a \
                and recv_packet[2] == 0x4c \
                and recv_packet[3] == 0x49 \
                and recv_packet[4] == 0x4e \
                and recv_packet[5] == 0x4b \
                and recv_packet[6] == 0x20 \
                and recv_packet[7] == 0x45 \
                and recv_packet[8] == 0x52 \
                and recv_packet[9] == 0x52 \
                and recv_packet[10]== 0x41 \
                and recv_packet[11]== 0x0d:
                    err_code = ErrorCode.NO_ERROR
                    pjlink_resp = ResponseCode.PasswordIsMismatch
                else: # unknown error
                        err_code = ErrorCode.RECV_INVALID_PACKET_ERROR

            elif len(recv_packet) >= 8 and recv_packet[(len(recv_packet)-1)] == 0x0d: # OK? check minimum len and terminating
                # check header  % N A M E =
                if  recv_packet[0] == 0x25 \
                and recv_packet[1] == 0x31 \
                and recv_packet[2] == 0x4e \
                and recv_packet[3] == 0x41 \
                and recv_packet[4] == 0x4d \
                and recv_packet[5] == 0x45 \
                and recv_packet[6] == 0x3d:
                    
                    # parse packet
                    invalid_flag = False
                    pjname = ""
                    pos = 7

                    if recv_packet[pos] == 0x0d:
                        pass # There is no name.
                    else:
                        for cnt in range(self.__MAX_PJ_NAME_LEN):
                            if (pos+cnt) > (len(recv_packet) - 1):
                                invalid_flag = True
                                break

                            if recv_packet[pos+cnt] == 0x0d:
                                break
                            else: # encoding by utf-8 
                                pjname += str((recv_packet[pos+cnt]).to_bytes(1, 'little'), encoding="utf-8", errors="replace")

                    # result
                    if invalid_flag == True:
                        err_code = ErrorCode.RECV_INVALID_PACKET_ERROR
                    else:
                        err_code = ErrorCode.NO_ERROR
                        pjlink_resp = ResponseCode.NoError
                        pjlink_request_result["Projector name"] = pjname

            else: # packet length error
                err_code = ErrorCode.RECV_INVALID_PACKET_ERROR

        # set error_code
        cmd_result.SetErrorCode(err_code)
        cmd_result.SetPJLinkResponseCode(pjlink_resp)
        cmd_result.ReplacePJLinkRequestResult(pjlink_request_result)

        # set communication packets for debug and development
        if len(send_packet):
            cmd_result.SetSentPacket(send_packet)
        if len(recv_packet):
            cmd_result.SetReceivedPacket(recv_packet)

        return cmd_result


    def GetProjectorName(self):
        ret = CommandResult()
        if self.__is_connected == False:
            ret.SetErrorCode(ErrorCode.CONNECTION_ERROR)
        else:
            if self.__connection_type == ConnectionType.TCP:
                ret = self.__getProjectorName_CmdBody(self.__connection_type)
            else:
                ret.SetErrorCode(ErrorCode.CONNECTION_TYPE_ERROR)
        return ret
    

    ### get manufacture name (INF1)
    __MAX_MANU_NAME_LEN = 32
    def __getManufactureName_CmdBody(self, connection_type):
        cmd_result = CommandResult()
        # % 1 I N F 1 SP ? CR
        send_packet = array.array('B', [0x25, 0x31, 0x49, 0x4e, 0x46, 0x31, 0x20, 0x3f, 0x0d])
        recv_packet = array.array('B', [])

        # if the password is enabled, adding a digest code
        if self.__pjlink_password_enabled == True:
            send_packet_with_pass = array.array('B', [])
            for value in self.__pjlink_crypted_digest_list:
                send_packet_with_pass.append(value)
            send_packet_with_pass.extend(send_packet)
            send_packet = send_packet_with_pass

        # execute send and receive
        err_code = self.__impl_send_receive_packet(send_packet, recv_packet, connection_type)

        # check received packet
        pjlink_resp = ResponseCode.Indefinite
        pjlink_request_result = {}
        if err_code == ErrorCode.NO_ERROR:

            if len(recv_packet) == 12 and recv_packet[0] == 0x25: # Error?
                # % 1 I N F 1 = E R R X CR
                if  recv_packet[0] == 0x25 \
                and recv_packet[1] == 0x31 \
                and recv_packet[2] == 0x49 \
                and recv_packet[3] == 0x4e \
                and recv_packet[4] == 0x46 \
                and recv_packet[5] == 0x31 \
                and recv_packet[6] == 0x3d \
                and recv_packet[7] == 0x45 \
                and recv_packet[8] == 0x52 \
                and recv_packet[9] == 0x52 \
                and recv_packet[11] == 0x0d:
                    if recv_packet[10] == 0x33: # ERR3
                        err_code = ErrorCode.NO_ERROR
                        pjlink_resp = ResponseCode.UnacceptablePeriod
                    elif recv_packet[10] == 0x34: # ERR4
                        err_code = ErrorCode.NO_ERROR
                        pjlink_resp = ResponseCode.DisplayDeviceIsError
                    else: # unknown error
                        err_code = ErrorCode.RECV_INVALID_PACKET_ERROR

            elif len(recv_packet) == 12 and recv_packet[0] == 0x50: # Authentication error?
                # P J L I N K SP E R R A CR
                if  recv_packet[0] == 0x50 \
                and recv_packet[1] == 0x4a \
                and recv_packet[2] == 0x4c \
                and recv_packet[3] == 0x49 \
                and recv_packet[4] == 0x4e \
                and recv_packet[5] == 0x4b \
                and recv_packet[6] == 0x20 \
                and recv_packet[7] == 0x45 \
                and recv_packet[8] == 0x52 \
                and recv_packet[9] == 0x52 \
                and recv_packet[10]== 0x41 \
                and recv_packet[11]== 0x0d:
                    err_code = ErrorCode.NO_ERROR
                    pjlink_resp = ResponseCode.PasswordIsMismatch
                else: # unknown error
                        err_code = ErrorCode.RECV_INVALID_PACKET_ERROR

            elif len(recv_packet) >= 8 and recv_packet[(len(recv_packet)-1)] == 0x0d: # OK? check minimum len and terminating
                # check header  % I N F 1 =
                if  recv_packet[0] == 0x25 \
                and recv_packet[1] == 0x31 \
                and recv_packet[2] == 0x49 \
                and recv_packet[3] == 0x4e \
                and recv_packet[4] == 0x46 \
                and recv_packet[5] == 0x31 \
                and recv_packet[6] == 0x3d:
                    
                    # parse packet
                    invalid_flag = False
                    tmp_str = ""
                    pos = 7

                    if recv_packet[pos] == 0x0d:
                        pass # There is no string.
                    else:
                        for cnt in range(self.__MAX_MANU_NAME_LEN):
                            if (pos+cnt) > (len(recv_packet) - 1):
                                invalid_flag = True
                                break

                            if recv_packet[pos+cnt] == 0x0d:
                                break
                            else: # encoding by ascii 
                                if (recv_packet[pos+cnt] >= 0x20) and (recv_packet[pos+cnt] <= 0x7e):
                                    tmp_str += str((recv_packet[pos+cnt]).to_bytes(1, 'little'), encoding="ascii", errors="replace")
                                else:
                                    invalid_flag = True
                                    break
                                
                    # result
                    if invalid_flag == True:
                        err_code = ErrorCode.RECV_INVALID_PACKET_ERROR
                    else:
                        err_code = ErrorCode.NO_ERROR
                        pjlink_resp = ResponseCode.NoError
                        pjlink_request_result["Manufacture name"] = tmp_str

            else: # packet length error
                err_code = ErrorCode.RECV_INVALID_PACKET_ERROR

        # set error_code
        cmd_result.SetErrorCode(err_code)
        cmd_result.SetPJLinkResponseCode(pjlink_resp)
        cmd_result.ReplacePJLinkRequestResult(pjlink_request_result)

        # set communication packets for debug and development
        if len(send_packet):
            cmd_result.SetSentPacket(send_packet)
        if len(recv_packet):
            cmd_result.SetReceivedPacket(recv_packet)

        return cmd_result


    def GetManufactureName(self):
        ret = CommandResult()
        if self.__is_connected == False:
            ret.SetErrorCode(ErrorCode.CONNECTION_ERROR)
        else:
            if self.__connection_type == ConnectionType.TCP:
                ret = self.__getManufactureName_CmdBody(self.__connection_type)
            else:
                ret.SetErrorCode(ErrorCode.CONNECTION_TYPE_ERROR)
        return ret
    

    ### get product name (INF2)
    __MAX_PRODUCT_NAME_LEN = 32
    def __getProductName_CmdBody(self, connection_type):
        cmd_result = CommandResult()
        # % 1 I N F 2 SP ? CR
        send_packet = array.array('B', [0x25, 0x31, 0x49, 0x4e, 0x46, 0x32, 0x20, 0x3f, 0x0d])
        recv_packet = array.array('B', [])

        # if the password is enabled, adding a digest code
        if self.__pjlink_password_enabled == True:
            send_packet_with_pass = array.array('B', [])
            for value in self.__pjlink_crypted_digest_list:
                send_packet_with_pass.append(value)
            send_packet_with_pass.extend(send_packet)
            send_packet = send_packet_with_pass

        # execute send and receive
        err_code = self.__impl_send_receive_packet(send_packet, recv_packet, connection_type)

        # check received packet
        pjlink_resp = ResponseCode.Indefinite
        pjlink_request_result = {}
        if err_code == ErrorCode.NO_ERROR:

            if len(recv_packet) == 12 and recv_packet[0] == 0x25: # Error?
                # % 1 I N F 2 = E R R X CR
                if  recv_packet[0] == 0x25 \
                and recv_packet[1] == 0x31 \
                and recv_packet[2] == 0x49 \
                and recv_packet[3] == 0x4e \
                and recv_packet[4] == 0x46 \
                and recv_packet[5] == 0x32 \
                and recv_packet[6] == 0x3d \
                and recv_packet[7] == 0x45 \
                and recv_packet[8] == 0x52 \
                and recv_packet[9] == 0x52 \
                and recv_packet[11] == 0x0d:
                    if recv_packet[10] == 0x33: # ERR3
                        err_code = ErrorCode.NO_ERROR
                        pjlink_resp = ResponseCode.UnacceptablePeriod
                    elif recv_packet[10] == 0x34: # ERR4
                        err_code = ErrorCode.NO_ERROR
                        pjlink_resp = ResponseCode.DisplayDeviceIsError
                    else: # unknown error
                        err_code = ErrorCode.RECV_INVALID_PACKET_ERROR

            elif len(recv_packet) == 12 and recv_packet[0] == 0x50: # Authentication error?
                # P J L I N K SP E R R A CR
                if  recv_packet[0] == 0x50 \
                and recv_packet[1] == 0x4a \
                and recv_packet[2] == 0x4c \
                and recv_packet[3] == 0x49 \
                and recv_packet[4] == 0x4e \
                and recv_packet[5] == 0x4b \
                and recv_packet[6] == 0x20 \
                and recv_packet[7] == 0x45 \
                and recv_packet[8] == 0x52 \
                and recv_packet[9] == 0x52 \
                and recv_packet[10]== 0x41 \
                and recv_packet[11]== 0x0d:
                    err_code = ErrorCode.NO_ERROR
                    pjlink_resp = ResponseCode.PasswordIsMismatch
                else: # unknown error
                        err_code = ErrorCode.RECV_INVALID_PACKET_ERROR

            elif len(recv_packet) >= 8 and recv_packet[(len(recv_packet)-1)] == 0x0d: # OK? check minimum len and terminating
                # check header  % I N F 2 =
                if  recv_packet[0] == 0x25 \
                and recv_packet[1] == 0x31 \
                and recv_packet[2] == 0x49 \
                and recv_packet[3] == 0x4e \
                and recv_packet[4] == 0x46 \
                and recv_packet[5] == 0x32 \
                and recv_packet[6] == 0x3d:
                    
                    # parse packet
                    invalid_flag = False
                    tmp_str = ""
                    pos = 7

                    if recv_packet[pos] == 0x0d:
                        pass # There is no string.
                    else:
                        for cnt in range(self.__MAX_PRODUCT_NAME_LEN):
                            if (pos+cnt) > (len(recv_packet) - 1):
                                invalid_flag = True
                                break

                            if recv_packet[pos+cnt] == 0x0d:
                                break
                            else: # encoding by ascii
                                if (recv_packet[pos+cnt] >= 0x20) and (recv_packet[pos+cnt] <= 0x7e):
                                    tmp_str += str((recv_packet[pos+cnt]).to_bytes(1, 'little'), encoding="ascii", errors="replace")
                                else:
                                    invalid_flag = True
                                    break
                                
                    # result
                    if invalid_flag == True:
                        err_code = ErrorCode.RECV_INVALID_PACKET_ERROR
                    else:
                        err_code = ErrorCode.NO_ERROR
                        pjlink_resp = ResponseCode.NoError
                        pjlink_request_result["Product name"] = tmp_str

            else: # packet length error
                err_code = ErrorCode.RECV_INVALID_PACKET_ERROR

        # set error_code
        cmd_result.SetErrorCode(err_code)
        cmd_result.SetPJLinkResponseCode(pjlink_resp)
        cmd_result.ReplacePJLinkRequestResult(pjlink_request_result)

        # set communication packets for debug and development
        if len(send_packet):
            cmd_result.SetSentPacket(send_packet)
        if len(recv_packet):
            cmd_result.SetReceivedPacket(recv_packet)

        return cmd_result


    def GetProductName(self):
        ret = CommandResult()
        if self.__is_connected == False:
            ret.SetErrorCode(ErrorCode.CONNECTION_ERROR)
        else:
            if self.__connection_type == ConnectionType.TCP:
                ret = self.__getProductName_CmdBody(self.__connection_type)
            else:
                ret.SetErrorCode(ErrorCode.CONNECTION_TYPE_ERROR)
        return ret
    

    ### get other information (INFO)
    __MAX_OTHER_INFO_LEN = 32
    def __getOtherInformation_CmdBody(self, connection_type):
        cmd_result = CommandResult()
        # % 1 I N F O SP ? CR
        send_packet = array.array('B', [0x25, 0x31, 0x49, 0x4e, 0x46, 0x4f, 0x20, 0x3f, 0x0d])
        recv_packet = array.array('B', [])

        # if the password is enabled, adding a digest code
        if self.__pjlink_password_enabled == True:
            send_packet_with_pass = array.array('B', [])
            for value in self.__pjlink_crypted_digest_list:
                send_packet_with_pass.append(value)
            send_packet_with_pass.extend(send_packet)
            send_packet = send_packet_with_pass

        # execute send and receive
        err_code = self.__impl_send_receive_packet(send_packet, recv_packet, connection_type)

        # check received packet
        pjlink_resp = ResponseCode.Indefinite
        pjlink_request_result = {}
        if err_code == ErrorCode.NO_ERROR:

            if len(recv_packet) == 12 and recv_packet[0] == 0x25: # Error?
                # % 1 I N F O = E R R X CR
                if  recv_packet[0] == 0x25 \
                and recv_packet[1] == 0x31 \
                and recv_packet[2] == 0x49 \
                and recv_packet[3] == 0x4e \
                and recv_packet[4] == 0x46 \
                and recv_packet[5] == 0x4f \
                and recv_packet[6] == 0x3d \
                and recv_packet[7] == 0x45 \
                and recv_packet[8] == 0x52 \
                and recv_packet[9] == 0x52 \
                and recv_packet[11] == 0x0d:
                    if recv_packet[10] == 0x33: # ERR3
                        err_code = ErrorCode.NO_ERROR
                        pjlink_resp = ResponseCode.UnacceptablePeriod
                    elif recv_packet[10] == 0x34: # ERR4
                        err_code = ErrorCode.NO_ERROR
                        pjlink_resp = ResponseCode.DisplayDeviceIsError
                    else: # unknown error
                        err_code = ErrorCode.RECV_INVALID_PACKET_ERROR

            elif len(recv_packet) == 12 and recv_packet[0] == 0x50: # Authentication error?
                # P J L I N K SP E R R A CR
                if  recv_packet[0] == 0x50 \
                and recv_packet[1] == 0x4a \
                and recv_packet[2] == 0x4c \
                and recv_packet[3] == 0x49 \
                and recv_packet[4] == 0x4e \
                and recv_packet[5] == 0x4b \
                and recv_packet[6] == 0x20 \
                and recv_packet[7] == 0x45 \
                and recv_packet[8] == 0x52 \
                and recv_packet[9] == 0x52 \
                and recv_packet[10]== 0x41 \
                and recv_packet[11]== 0x0d:
                    err_code = ErrorCode.NO_ERROR
                    pjlink_resp = ResponseCode.PasswordIsMismatch
                else: # unknown error
                        err_code = ErrorCode.RECV_INVALID_PACKET_ERROR

            elif len(recv_packet) >= 8 and recv_packet[(len(recv_packet)-1)] == 0x0d: # OK? check minimum len and terminating
                # check header  % I N F O =
                if  recv_packet[0] == 0x25 \
                and recv_packet[1] == 0x31 \
                and recv_packet[2] == 0x49 \
                and recv_packet[3] == 0x4e \
                and recv_packet[4] == 0x46 \
                and recv_packet[5] == 0x4f \
                and recv_packet[6] == 0x3d:
                    
                    # parse packet
                    invalid_flag = False
                    tmp_str = ""
                    pos = 7

                    if recv_packet[pos] == 0x0d:
                        pass # There is no string.
                    else:
                        for cnt in range(self.__MAX_OTHER_INFO_LEN):
                            if (pos+cnt) > (len(recv_packet) - 1):
                                invalid_flag = True
                                break

                            if recv_packet[pos+cnt] == 0x0d:
                                break
                            else: # encoding by ascii 
                                if (recv_packet[pos+cnt] >= 0x20) and (recv_packet[pos+cnt] <= 0x7e):
                                    tmp_str += str((recv_packet[pos+cnt]).to_bytes(1, 'little'), encoding="ascii", errors="replace")
                                else:
                                    invalid_flag = True
                                    break
                                
                    # result
                    if invalid_flag == True:
                        err_code = ErrorCode.RECV_INVALID_PACKET_ERROR
                    else:
                        err_code = ErrorCode.NO_ERROR
                        pjlink_resp = ResponseCode.NoError
                        pjlink_request_result["Other info"] = tmp_str

            else: # packet length error
                err_code = ErrorCode.RECV_INVALID_PACKET_ERROR

        # set error_code
        cmd_result.SetErrorCode(err_code)
        cmd_result.SetPJLinkResponseCode(pjlink_resp)
        cmd_result.ReplacePJLinkRequestResult(pjlink_request_result)

        # set communication packets for debug and development
        if len(send_packet):
            cmd_result.SetSentPacket(send_packet)
        if len(recv_packet):
            cmd_result.SetReceivedPacket(recv_packet)

        return cmd_result


    def GetOtherInformation(self):
        ret = CommandResult()
        if self.__is_connected == False:
            ret.SetErrorCode(ErrorCode.CONNECTION_ERROR)
        else:
            if self.__connection_type == ConnectionType.TCP:
                ret = self.__getOtherInformation_CmdBody(self.__connection_type)
            else:
                ret.SetErrorCode(ErrorCode.CONNECTION_TYPE_ERROR)
        return ret
    

    ### get class information
    def __getClassInformation_CmdBody(self, connection_type):
        cmd_result = CommandResult()
        # % 1 C L S S SP ? CR
        send_packet = array.array('B', [0x25, 0x31, 0x43, 0x4c, 0x53, 0x53, 0x20, 0x3f, 0x0d])
        recv_packet = array.array('B', [])

        # if the password is enabled, adding a digest code
        if self.__pjlink_password_enabled == True:
            send_packet_with_pass = array.array('B', [])
            for value in self.__pjlink_crypted_digest_list:
                send_packet_with_pass.append(value)
            send_packet_with_pass.extend(send_packet)
            send_packet = send_packet_with_pass

        # execute send and receive
        err_code = self.__impl_send_receive_packet(send_packet, recv_packet, connection_type)

        # check received packet
        pjlink_resp = ResponseCode.Indefinite
        pjlink_request_result = {}
        if err_code == ErrorCode.NO_ERROR:

            if len(recv_packet) == 12 and recv_packet[0] == 0x25: # Error?
                # % 1 C L S S = E R R X CR
                if  recv_packet[0] == 0x25 \
                and recv_packet[1] == 0x31 \
                and recv_packet[2] == 0x43 \
                and recv_packet[3] == 0x4c \
                and recv_packet[4] == 0x53 \
                and recv_packet[5] == 0x53 \
                and recv_packet[6] == 0x3d \
                and recv_packet[7] == 0x45 \
                and recv_packet[8] == 0x52 \
                and recv_packet[9] == 0x52 \
                and recv_packet[11] == 0x0d:
                    if recv_packet[10] == 0x33: # ERR3
                        err_code = ErrorCode.NO_ERROR
                        pjlink_resp = ResponseCode.UnacceptablePeriod
                    elif recv_packet[10] == 0x34: # ERR4
                        err_code = ErrorCode.NO_ERROR
                        pjlink_resp = ResponseCode.DisplayDeviceIsError
                    else: # unknown error
                        err_code = ErrorCode.RECV_INVALID_PACKET_ERROR

            elif len(recv_packet) == 12 and recv_packet[0] == 0x50: # Authentication error?
                # P J L I N K SP E R R A CR
                if  recv_packet[0] == 0x50 \
                and recv_packet[1] == 0x4a \
                and recv_packet[2] == 0x4c \
                and recv_packet[3] == 0x49 \
                and recv_packet[4] == 0x4e \
                and recv_packet[5] == 0x4b \
                and recv_packet[6] == 0x20 \
                and recv_packet[7] == 0x45 \
                and recv_packet[8] == 0x52 \
                and recv_packet[9] == 0x52 \
                and recv_packet[10]== 0x41 \
                and recv_packet[11]== 0x0d:
                    err_code = ErrorCode.NO_ERROR
                    pjlink_resp = ResponseCode.PasswordIsMismatch
                else: # unknown error
                        err_code = ErrorCode.RECV_INVALID_PACKET_ERROR

            elif len(recv_packet) == 9 and recv_packet[(len(recv_packet)-1)] == 0x0d: # OK? check length and terminating
                # check header  % C L S S =
                if  recv_packet[0] == 0x25 \
                and recv_packet[1] == 0x31 \
                and recv_packet[2] == 0x43 \
                and recv_packet[3] == 0x4c \
                and recv_packet[4] == 0x53 \
                and recv_packet[5] == 0x53 \
                and recv_packet[6] == 0x3d:
                    
                    # parse packet
                    if (recv_packet[7] == 0x31) or (recv_packet[7] == 0x32):
                        err_code = ErrorCode.NO_ERROR
                        pjlink_resp = ResponseCode.NoError
                        pjlink_request_result["PJLink Class"] = "Class2" if (recv_packet[7] == 0x32) else "Class1"
                    else:
                        err_code = ErrorCode.RECV_INVALID_PACKET_ERROR

            else: # packet length error
                err_code = ErrorCode.RECV_INVALID_PACKET_ERROR

        # set error_code
        cmd_result.SetErrorCode(err_code)
        cmd_result.SetPJLinkResponseCode(pjlink_resp)
        cmd_result.ReplacePJLinkRequestResult(pjlink_request_result)

        # set communication packets for debug and development
        if len(send_packet):
            cmd_result.SetSentPacket(send_packet)
        if len(recv_packet):
            cmd_result.SetReceivedPacket(recv_packet)

        return cmd_result


    def GetClassInformation(self):
        ret = CommandResult()
        if self.__is_connected == False:
            ret.SetErrorCode(ErrorCode.CONNECTION_ERROR)
        else:
            if self.__connection_type == ConnectionType.TCP:
                ret = self.__getClassInformation_CmdBody(self.__connection_type)
            else:
                ret.SetErrorCode(ErrorCode.CONNECTION_TYPE_ERROR)
        return ret
    
