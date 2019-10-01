import time
import uuid

from typing import List
from functools import reduce

from mitmproxy import flow
from mitmproxy import connections
from mitmproxy.utils import human
from mitmproxy.coretypes import serializable


class TCPMessage(serializable.Serializable):

    def __init__(self, from_client, content, flow, timestamp=None):
        self.from_client:bool  = from_client
        self.content = content
        self.id = str(uuid.uuid4())
        self.flow = flow 
        self.timestamp = timestamp or time.time()
        self.index = len(flow.messages)

    @classmethod 
    def from_state(cls, state):
        return cls(*state)

    def get_state(self):
        return self.from_client, self.content, self.timestamp

    def set_state(self, state):
        self.from_client, self.content, self.timestamp = state

    def __repr__(self):
        return "{client} {direction} {server}".format(
            direction="->" if self.from_client else "<-",
            client=human.format_address(self.flow.client_conn.address),
            server=human.format_address(self.flow.server_conn.address)
        )

    @property 
    def raw_content(self):
        content = bytes() 
        for message in self.messages:
            content += message.content
        return content


class TCPFlow(flow.Flow):

    """
    A TCPFlow is a simplified representation of a TCP session.
    """

    def __init__(self, client_conn, server_conn, stream_index, live=None):
        super().__init__("tcp", client_conn, server_conn, live)
        self.client_conn = client_conn
        self.server_conn = server_conn
        self.messages: List[TCPMessage] = []
        self.index = stream_index


    _stateobject_attributes = flow.Flow._stateobject_attributes.copy()
    _stateobject_attributes["messages"] = List[TCPMessage]
    #_stateobject_attributes["server"] = TCPBase 
    #_stateobject_attributes["client"] = TCPBase 
    #_stateobject_attributes["client"] = TCPBase 


    def __repr__(self):
        return "<TCPFlow ({} messages)>".format(len(self.messages))

    def new_message(self, message: TCPMessage):
        self.messages.append(message)

    @property 
    def raw_content(self):
        content = bytes() 
        for message in self.messages:
            content += message.content
        return content

    @property
    def client_messages(self):
        return self.all_messages(True)

    @property
    def server_messages(self):
        return self.all_messages(False)
    @property
    def client_stream(self):
        return TCPSteam(self.client_conn, self.server_conn, self.all_messages(True))

    @property
    def server_stream(self):
        return TCPSteam(self.client_conn, self.server_conn, self.all_messages(False))

    @property
    def timestamp(self):
        if len(self.messages) > 0:
            return self.messages[-1].timestamp
        else:
            return time.time()

    def all_messages(self, from_client):
        return list(filter(lambda message: message.from_client == from_client, self.messages))


class TCPSteam(TCPFlow):
    def __init__(self, client_conn, server_conn, messages):
        self.client_conn = client_conn
        self.server_conn = server_conn
        self.messages: List[TCPMessage] = messages
