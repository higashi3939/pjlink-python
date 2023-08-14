# 
# SocketCommTcpPy.py
#
# Copyright (C) 2023 higashi
# Released under the MIT license.
# Please see  https://opensource.org/licenses/MIT
#

import socket

class SocketCommTcpPy:

    # variables
    __is_connected = False
    __sock = None
    __bufsize = 1024


    def __init__(self):
        #print("SocketCommTcpPy: call construct")
        self.__is_connected = False
        self.__sock = None


    def __del__(self):
        #print("SocketCommTcpPy: call destruct")
        self.__closeSock()


    def __closeSock(self):
        if self.__is_connected == True:
            self.__is_connected = False
            self.__sock.close()
            self.__sock = None


    def CloseConnection(self):
        self.__closeSock()
        return None


    # Return: True or False
    def OpenConnection(self, target_ip_v4_str, port_num, socket_timeout_sec):
        if self.__is_connected == True:
            return False # already connected

        remote = (target_ip_v4_str, port_num)
        self.__sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.__sock.settimeout(socket_timeout_sec)

        try:
            self.__sock.connect(remote)
            self.__is_connected = True     
        except Exception as e:
            print("SocketCommTcpPy: Exception: %s" % e)
            self.__sock = None
            self.__is_connected = False

        return True if self.__is_connected == True else False


    # Return: Sent data num
    def Send(self, send_data_array, timeout_sec):
        if self.__is_connected == False:
            return 0

        self.__sock.settimeout(timeout_sec)
        ret = 0
        try:
            self.__sock.send(send_data_array)
            ret = len(send_data_array)
        except Exception as e:
            print("SocketCommTcpPy: Exception: %s" % e)

        return ret

    
    # Return: Received data array if succeed
    def Receive(self, timeout_sec):
        if self.__is_connected == False:
            return None

        self.__sock.settimeout(timeout_sec)
        ret = None
        try:
            tmp_recv = self.__sock.recv(self.__bufsize)
            ret = tmp_recv
        except Exception as e:
            print("SocketCommTcpPy: Exception: %s" % e)

        return ret

