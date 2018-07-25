#! /usr/bin/env python
"""File with all keywords required to test Trace TCP Server from a TCP client
"""

# ===============================
# Import BuildIn Python Libraries
# ===============================
import sys
import os
import socket
import csv
import time
import re

# ===================
# Utilities libraries
# ===================
# add resources\keywords\trace_tcp_server_test_keywords.py folder to libraries path
library_directory = os.path.normpath(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
sys.path.insert(0, library_directory)

from resources.keywords.logging_lib import RobotLoggerClass

__author__ = 'Javier Ochoa (uidj5418)'
__version__ = 'See MKS'

# ==============
# Robot Keywords
# ==============

__all__ = [

    # ------------------------
    # TCP client test keywords
    # ------------------------
    'create_new_tcp_client',
    'connect_tcp_client',
    'send_trace_tcp_command',
    'send_commands_from_file',
    'generate_csv_report',
    'disconnect_all_tcp_clients',
    'terminate_trace_tcp_server_connection'

    ]

# command to terminate Trace TCP Server connection
CLOSE_SERVER_COMMAND = "CLOSE"


def str_to_bool(string):
    """Converts a string to a boolean state( True / False )
    """
    # check if string is already boolean type to avoid analysis
    if isinstance(string, bool):
        return string
    elif string.strip() in ['True', 'true', 'Yes', 'yes']:
        return True
    elif string.strip() in ['False', 'false', 'No', 'no']:
        return False
    else:
        raise AssertionError("(strToBool) '{s}' is an invalid string for boolean conversion".format(s=string))


# ===================================================
# [CLASS] ExceptionClientDisconnected - Exception
# ===================================================
class ExceptionClientDisconnected(Exception):
    """Class for exception when TCP Client is disconnected
    """
    
    def __init__(self, clientObject):
        """ExceptionClientDisconnected constructor
        """
        self.client = clientObject
        self.strerror = ("'{client}' disconnected".format(client=self.client.get_id()))

    def __str__(self):
        """exception string representation
        """
        errorMsg = ("<{client}> is disconnected".format(client=self.client.get_id()))
        return errorMsg


# ===================================================
# [CLASS] TcpClientHandler - Global variable Class
# ===================================================
class TcpClientHandler(object):
    """Class for tcp client management
    """
    
    def __init__(self):
        """Constructor for TcpClientHandler
        """
        self._client_container = {}

    def has_clients(self):
        """Returns True if the global handler has any client loaded.
        Otherwise returns False
        """
        if len(self._client_container) == 0:
            return False
        return True

    def add_client(self, client):
        """Add a tcp client instance to the handler for further management
        """
        self._client_container[client.get_id()] = client
        TCPLogger.info("New client added to the manager container: '{name}'".format(
            name=client.get_id()))

    def get_client(self, client_id):
        """Returns a Tcp Client instance that corresponds to
        the client_id string set. Otherwise returns None
        """
        client = None
        if client_id in self._client_container.keys():
            client = self._client_container[client_id]
        return client

    def get_all_clients(self):
        """Returns a dictionary with all the current tcp clients
        """
        return self._client_container

    def disconnect_all_clients(self):
        """Disconnects all the current active clients from the server
        """
        if self.has_clients():
            TCPLogger.info(
                "Disconnect all clients from server. "
                "Current client count: {clients}".format(
                    clients=len(self.get_all_clients())))
            for client in self.get_all_clients().values():
                client.disconnect()
                del client
        else:
            TCPLogger.warning("There are no clients to disconnect from server")


# ===================================================
# [CLASS] TcpClient - Global variable Class
# ===================================================
class TcpClient(object):
    """
    """
    
    # socket buffer settings
    BUFFER_SIZE = 1024
    # constants for CSV header
    __CSV_HEADER_TCP_COMMAND =      "TCP_COMMAND"
    __CSV_HEADER_RESPONSE =         "RESPONSE"
    __CSV_HEADER_EXPECTED_WORD =    "EXPECTED_WORD"
    __CSV_HEADER_VALIDATION =       "VALIDATION"

    # ----------------------------
    # Inner Class: CommandLog
    # ----------------------------
    class CommandLog(object):
        """Class for command log management.
        These logs contain information about each tcp command sent to server.
        Command String, Response to that command and the expected response validation
        """
        # constant for VALIDATION
        PASSED = "PASSED"
        # constant for INVALIDATION
        FAIL = "[ FAIL ]"
        # constant for something not applicable
        NOT_APPLICABLE = "N/A"

        def __init__(self, command, response, expected_word=None, match_case=False):
            """Constructor for CommandLog Class

            :param command: (string) command that was sent
            :param response: (string) response received from server for command
            :param expected_word: (string) expected word to be contained on the response
            """
            self._command = command
            self._response = response
            self._expectedWord = expected_word
            self._match_case = match_case

        def get_command(self):
            """Returns a string with the command send
            """
            return self._command

        def case_should_match(self):
            """Returns True if case should match
            in the command response and the expected response
            """
            if self._match_case:
                return True
            return False

        def get_response(self):
            """Returns a string with the command response
            """
            if self.case_should_match():
                return self._response
            else:
                return self._response.upper()

        def get_expected_word(self):
            """Returns a string with the expected word
            """
            if self.case_should_match():
                return self._expectedWord
            else:
                return self._expectedWord.upper()

        def get_validation(self):
            """Returns a string with the corresponding validation of a command
            if the expected word was contained on the command response, the
            validation would be PASSED. If not, it would be FAIL. When there is
            not word expected, N/A will be returned
            """
            if self.get_expected_word() is not None:
                # validate if the expected word was contained on the response
                if self.get_expected_word() in self.get_response():
                    # PASSED
                    return TcpClient.CommandLog.PASSED
                # FAIL
                return TcpClient.CommandLog.FAIL
            # validation is not applicable
            return TcpClient.CommandLog.NOT_APPLICABLE

    def __init__(self, name_identifier, host_ip_address='localhost'):
        """Constructor for TcpClient Class

        :param name_identifier: (string) with the tcp name for identification
        :param host_ip_address: (string) with the tcp client ip address
        """
        # Create a TCP/IP socket
        self._connection = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM )
        self._connection.settimeout(2)
        self._connected = False
        # client connection settings
        self._id = name_identifier
        self._host_ip_address = host_ip_address
        self._server_ip_address = None
        self._server_port = None
        # command file settings
        self._command_file = None
        self._command_list = []
        # csv file settings
        self._csv_file_object = None
        self._csv_file_writer = None
        self._csv_file_name = None
        self._first_response = None
        # a command log container for command status report (CSV)
        self._command_log_list = []
        TCPLogger.info("<{name}> TCP Client created with ip: ({ip})".format(
            name=self._id,
            ip=self._host_ip_address))

    def get_id(self):
        """Returns a string with the tcp client ID
        """
        return self._id

    def is_connected(self):
        """Returns True if client is connected to a server.
        Otherwise, returns False.
        """
        return self._connected

    def connect(self, server_address, server_port):
        """tries to connect the tcp client to a server
        with a configured address and port number
        """
        try:
            TCPLogger.info(
                "<{client_id}> connecting to Server ( {serverIp} : {serverPort} )".format(
                    client_id=self.get_id(),
                    serverIp=server_address,
                    serverPort=server_port))
            self._connection.connect((server_address, int(server_port)))
        except socket.error as detail:
            self._connected = False
            self._connection.close()
            error_msg = (
                "<{client_id}> client could not connect to server "
                "( {ip} : {port} ) detail: {error}".format(
                    client_id=self.get_id(),
                    ip=self._server_ip_address,
                    port=self._server_port,
                    error=detail))
            time.sleep(1)
            raise AssertionError(error_msg)
        else:
            # client successfully connected to server
            self._connected = True
            self._server_ip_address = server_address
            self._server_port = server_port
            TCPLogger.info(
                "<{client_id}> client successfully connected to Server "
                "( {serverIp} : {serverPort} )".format(
                    client_id=self.get_id(),
                    serverIp=self._server_ip_address,
                    serverPort=self._server_port))
        # receive the first response from the server after connection
        self._first_response = self.receive_response()

    def disconnect(self):
        """disconnects the client from the server connection
        """
        self._connected = False
        self._connection.close()
        time.sleep(1)
        TCPLogger.info(
            "<{client_id}> client disconnected from server".format(
                client_id=self.get_id()))

    def send_commands_from_file(self, filename):
        """Loads and validates a filename with tcp commands
        and sends it to the server
        """
        # validate filename, parse it and load all commands to be sent
        error_msg = self._load_command_file(filename)
        if error_msg is None:
            # go through all loaded commands retrieved from the file
            for command in self._command_list:
                tcp_command = None
                expected_word = None
                # remove line feed
                if command.endswith('\n'):
                    command = command.replace('\n', '')
                # split string to see if command has an expected word
                command_string = command.split(',')
                # verify expected word in the command string
                if len(command_string) > 1:
                    expected_word = command_string[1].strip()
                tcp_command = command_string[0].strip()
                # send actual tcp command
                response, word_in_response = self.send_command(tcp_command, expected_word)
                TCPLogger.info(
                    "<{client_id}> command file: CMD: '{cmd}' : '{res}' ".format(
                        client_id=self.get_id(),
                        cmd=tcp_command,
                        res=response))
        else:
            raise AssertionError(error_msg)

    def send_message(self, string_message):
        """Sends a string message through the socket
        """
        if self.is_connected():
            try:
                # encode message to bytes + new line
                message = str.encode(string_message + os.linesep)
                # send data through socket connection
                self._connection.sendall(message)
            except socket.error as detail:
                TCPLogger.warning("<{client_id}> could not send message: {error}".format(
                    client_id=self.get_id(),
                    error=detail))
        else:
            raise ExceptionClientDisconnected(self)
            
    def receive_response(self):
        """Returns the data hold as a response from the socket
        """
        reception_data = None
        if self.is_connected():
            # create data reception
            reception_data = bytes()
            while True:
                try:
                    data = self._connection.recv(TcpClient.BUFFER_SIZE)
                    reception_data = reception_data + data
                except socket.timeout:
                    break
                except socket.error as detail:
                    TCPLogger.warning("<{client_id}> socket error at reception: {error}".format(
                        client_id=self.get_id(),
                        error=detail))
                    break
            reception_data = reception_data.decode('UTF-8')
        else:
            raise ExceptionClientDisconnected(self)
        return reception_data
        
    def send_command(self, command, match_expected_word=None, match_case=False):
        """Sends a trace tcp command to the server
        and it returns the response along with a flag
        in case the expected word was found on the response
        """
        response = None
        expected_word_found = False
        if self.is_connected():
            # send data through socket connection
            TCPLogger.info("<{client_id}> sending command: '{command}'".format(
                client_id=self.get_id(),
                command=command))
            self.send_message(command)
            response = self.receive_response()
            # remove line feed from response (if any)
            if response.endswith('\r\n'):
                response = response[:-2]
            TCPLogger.info("<{client_id}> receive response: '{cmdResponse}'".format(
                client_id=self.get_id(),
                cmdResponse=response))
            # validate if certain word is expected to be received on the response
            if match_expected_word is not None:
                # validate if expected word should match with case sensitive
                if str_to_bool(match_case):
                    # MATCH CASE IN RESPONSE
                    if str(match_expected_word) in response:
                        expected_word_found = True
                else:
                    # FOUND WORD IN RESPONSE (no case sensitivity)
                    if str(match_expected_word).upper() in response.upper():
                        expected_word_found = True
            # create a command log for the CSV report
            cmd_log = TcpClient.CommandLog(command, response, match_expected_word)
            self._command_log_list.append(cmd_log)
        else:
            raise ExceptionClientDisconnected(self)
        return response, expected_word_found

    def generate_csv_report(self, csv_filename):
        """Generates a CSV report on the csv filename configured
        with all the command logs created when tcp commands were sent
        """
        error_msg = None
        # validates if the configured csv filename exists
        self._csv_file_name = self._validate_csv_file(csv_filename)
        # set the error message in case of invalidation
        if self._csv_file_name is None:
            error_msg = "Invalid file name for CSV report generation: '{csv_file}'".format(
                csv_file=csv_filename)
        if error_msg is None:
            # build the fields on the header of the csv file report
            fieldNameList = (
                TcpClient.__CSV_HEADER_TCP_COMMAND,
                TcpClient.__CSV_HEADER_RESPONSE,
                TcpClient.__CSV_HEADER_EXPECTED_WORD,
                TcpClient.__CSV_HEADER_VALIDATION
                )
            # generate the csv file
            with open(self._csv_file_name, mode='w', newline='') as csvFile:
                #
                writer = csv.DictWriter(
                    csvFile,
                    fieldnames=fieldNameList,
                    extrasaction='ignore',
                    delimiter=',')
                writer.writeheader()
                # dictionary for command log representation on CSV
                csv_dict = {}
                # go through all command logs, retrieve data and build CSV data
                for cmd in self._command_log_list:
                    csv_dict[TcpClient.__CSV_HEADER_TCP_COMMAND] = cmd.get_command()
                    csv_dict[TcpClient.__CSV_HEADER_RESPONSE] = cmd.get_response()
                    csv_dict[TcpClient.__CSV_HEADER_EXPECTED_WORD] = cmd.get_expected_word()
                    csv_dict[TcpClient.__CSV_HEADER_VALIDATION] = cmd.get_validation()
                    writer.writerow(csv_dict)
            TCPLogger.info("CSV report successfully generated: '{csv_report}'".format(
                csv_report=self._csv_file_name))
        return self._csv_file_name, error_msg

    def _load_command_file(self, filename):
        """Validates and retrieves all trace tcp commands from filename;
        """
        cmd_filename = os.path.normpath(filename)
        error_msg = None
        if os.path.exists(cmd_filename):
            # read all command from file and load them to the client
            with open(cmd_filename, mode='r') as cmdFile:
                self._command_list = cmdFile.readlines()
        else:
            error_msg = ("<{client_id}> command file does not exist: '{cmd_file}'".format(
                client_id=self.get_id(),
                cmd_file=filename))
        return error_msg

    def _validate_csv_file(self, filename):
        """Validates if filename has a valid CSV file structure and
        it also validates if the output directory exists
        """
        file_basename = os.path.normpath(os.path.basename(filename))
        # match filename to have the csv file structure
        filename_match = re.search("[\w\s]*.csv$", file_basename)
        csv_filename = None
        if filename_match is not None:
            TCPLogger.info("Validate output directory for CSV generation: '{dir}'".format(
                dir=os.path.dirname(filename)))
            # check if the directory to the configured csv file exists
            if os.path.exists(os.path.dirname(filename)):
                csv_filename = os.path.normpath(filename)
            else:
                TCPLogger.warning("Output directory for CSV generation does not exist: '{dir}'".format(
                    dir=os.path.dirname(filename)))
        else:
            TCPLogger.warning("CSV file name has an invalid structure: '{filename}'".format(
                filename=file_basename))
        return csv_filename

#------------------
# Global Instances
#------------------

# create a global TCP Logger for debugging purposes
TCPLogger = RobotLoggerClass("TRACE_TCP_TESTER")

# create a global Trace TCP Client handler for testing
TraceTcpClientHandler = TcpClientHandler()

#===================================================================================#
#===================================================================================#
#                                                                                   #
#                              ---- TCP KEYWORDS ----                               #
#                                                                                   #
#===================================================================================#
#===================================================================================#


# ========================================
# [KEYWORD] create new tcp client
# ========================================
def create_new_tcp_client(identifier_name, client_ip_address=None):
    """
    Creates a new instance for a tcp client and returns the
    name identifier to that client
            
    Parameters:
    - [identifier_name] -- The tcp client identifier name
    - [client_ip_address] -- the ip address for this tcp client
            
    Returns:
    a string with the 'identifier_name' of the tcp client instance

    Example: 
    | ${client} | create_new_tcp_client | client_01 | 127.0.0.1 |
    """
    tcp_client = None
    if client_ip_address is None:
        tcp_client = TcpClient(
            name_identifier=identifier_name)
    else:
        tcp_client = TcpClient(
            name_identifier=identifier_name,
            host_ip_address=client_ip_address)
    # add the new tcp client to the global handler
    TraceTcpClientHandler.add_client(tcp_client)
    return tcp_client.get_id()


# ========================================
# [KEYWORD] connect tcp client
# ========================================
def connect_tcp_client(identifier_name, server_ip_address, server_port):
    """
    Connects a single client (identified by 'identifier_name') to a TCP
    server with the corresponding ip address and port number
            
    Parameters:
    - [identifier_name] -- The tcp client identifier name
    - [server_ip_address] -- the ip address of the TCP server to connect
    - [server_port] -- the port number of the TCP server to connect

    Returns:
    - None
            
    Example: 
    | connect_tcp_client | client_01 | 127.0.0.1 | 60000 |
    """
    # retrieve client name if it exists
    client = TraceTcpClientHandler.get_client(identifier_name)
    if client is not None:
        try:
            client.connect(server_ip_address, server_port)
        except Exception as detail:
            raise AssertionError("Cannot connect client with identifier '{id}' detail: ({error})".format(
                id=identifier_name,
                error=detail))
    else:
        raise AssertionError("TCP Client with identifier '{id}' not found".format(
            id=identifier_name))


# ========================================
# [KEYWORD] send trace tcp command
# ========================================
def send_trace_tcp_command(identifier_name, command, expected_word=None, expected_response=None, match_case=False):
    """
    Sends a trace TCP command from a TCP client to a server
            
    Parameters:
    - [identifier_name] -- The tcp client identifier name
    - [command] -- string with the trace tcp command
    - [expected_word] -- string with a word expected on the response of the command
    - [expected_response] -- string with the exact expected response of the command
    - [match_case] -- match the case sensitivity of the 'expected_word'/'expected_response'
            
    Returns:
    a string with the response received from the server of the tcp command
            
    Example: 
    | send trace tcp command |
    ...  client_01
    ...  my command arg_1 arg_2 arg_n
    ...  OK
    ...  your command is OK
    ...  True
    """
    # retrieve client name if it exists
    client = TraceTcpClientHandler.get_client(identifier_name)
    response = None
    if client is not None:
        try:
            # try to send the command and receive the response
            response, word_found = client.send_command(command, expected_word, match_case)
            # validate if a word was expected to be received in the response
            if expected_word is not None:
                if not word_found:
                    raise AssertionError(
                        "<{client_id}> Expected word '{word}' was not found "
                        "inside the command response: '{cmd_response}'".format(
                            client_id=client.get_id(),
                            word=expected_word,
                            cmd_response=response))
        except Exception as detail:
            raise AssertionError(detail)
    else:
        raise AssertionError("TCP Client with identifier '{id}' not found".format(id=identifier_name))
    return response


# ========================================
# [KEYWORD] send commands from file
# ========================================
def send_commands_from_file(identifier_name, command_file_name):
    """
    Parses a file with all tcp commands that should be sent to server
            
    Parameters:
    - [identifier_name] -- The tcp client identifier name
    - [command_file_name] -- a txt file with all the tcp commands
            
    Returns:
    - None
            
    Example: 
    | send commands from file | client_01 | path/my_cmd_list.txt |
    """
    # retrieve client name if it exists
    client = TraceTcpClientHandler.get_client(identifier_name)
    if client is not None:
        client.send_commands_from_file(command_file_name)
    else:
        raise AssertionError("TCP Client with identifier '{id}' not found".format(id=identifier_name))


# ==============================
# [] KEYWORD: XXX
# ==============================
def generate_csv_report(identifier_name, csv_file_name):
    """
    Generates a CSV file with a command status report
    in order to see which command failed or passed

    Parameters:
    - [identifier_name] -- The tcp client identifier name
    - [csv_file_name] -- the full filename for a CSV file

    Returns:
    a string with the filename in which the CSV file was generated

    Example:
    | ${csv_report} | generate csv report | client_01 | path/my_report.csv |
    """
    error_msg = None
    # retrieve client name if it exists
    client = TraceTcpClientHandler.get_client(identifier_name)
    if client is not None:
        # try to generate csv report and retrieve the filename
        file_name, error_msg = client.generate_csv_report(csv_file_name)
        if error_msg is None:
            return file_name
        else:
            raise AssertionError(error_msg)
    else:
        raise AssertionError("TCP Client with identifier '{id}' not found".format(id=identifier_name))


# ==============================
# [] KEYWORD: XXX
# ==============================
def disconnect_all_tcp_clients():
    """
    Disconnects all current active TCP clients that are connected
    to the TCP server

    Parameters:
    - None

    Returns:
    - None

    Example:
    | disconnect all tcp clients |
    """
    # disconnect all clients from the server
    TraceTcpClientHandler.disconnect_all_clients()


# ==============================
# [] KEYWORD: XXX
# ==============================
def terminate_trace_tcp_server_connection():
    """
    Tries to terminate the Trace TCP Server current session
    by sending a command responsible for closing the connection
    and the current server application

    Parameters:
    - None

    Returns:
    - None

    Example:
    | terminate trace tcp server connection |
    """
    # retrieve all current tcp clients
    tcp_clients = TraceTcpClientHandler.get_all_clients()
    if tcp_clients:
        for client in tcp_clients.values():
            # get the first available client in order to send a command
            if client.is_connected():
                # send the corresponding command to close server connection
                # and close the application
                TCPLogger.info(
                    "<{client_id}> Sending '{cmd}' command to terminate server connection".format(
                        client_id=client.get_id(),
                        cmd=CLOSE_SERVER_COMMAND))
                client.send_message(CLOSE_SERVER_COMMAND)
                break
        else:
            raise AssertionError("There was no tcp clients capable to terminate server connection")

#============
# DEBUG MODE
#============
if __name__ == "__main__":
    print(
"""
====================
===  DEBUG MODE  ===
====================
"""
    )
