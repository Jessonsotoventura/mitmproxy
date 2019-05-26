import time

from typing import List

from mitmproxy import flow
from mitmproxy import connections
from mitmproxy.coretypes import serializable


class TCPMessage(serializable.Serializable):

    def __init__(self, from_client, content, timestamp=None):
        self.from_client:bool  = from_client
        self.content = content
        self.timestamp = timestamp or time.time()

    @classmethod 
    def from_state(cls, state):
        return cls(*state)

    def get_state(self):
        return self.from_client, self.content, self.timestamp

    def set_state(self, state):
        self.from_client, self.content, self.timestamp = state

    def __repr__(self):
        return "{direction} {content}".format(
            direction="->" if self.from_client else "<-",
            content=repr(self.content)
        )

class TCPBase(serializable.Serializable):
 
    def __init__(self, conn):
        self.conn: connections.ClientConnection = conn
        self.messages: List[TCPMessage] = []

    @classmethod 
    def from_state(cls, state):
        return cls(*state)

    def get_state(self):
        return self.messages

    def set_state(self, state):
         self.messages = state

    @property 
    def raw_content(self):
        content = bytes() 
        for message in self.messages:
            content += message.content
        return content

    def new_message(self, message: TCPMessage):
        self.messages.append(message)


class TCPFlow(flow.Flow):

    """
    A TCPFlow is a simplified representation of a TCP session.
    """

    def __init__(self, client_conn, server_conn, live=None):
        super().__init__("tcp", client_conn, server_conn, live)
        self.client: TCPBase = TCPBase(client_conn)
        self.server: TCPBase = TCPBase(server_conn)
        self.messages: List[TCPMessage] = []


    _stateobject_attributes = flow.Flow._stateobject_attributes.copy()
    _stateobject_attributes["messages"] = List[TCPMessage]
    #_stateobject_attributes["server"] = TCPBase 
    #_stateobject_attributes["client"] = TCPBase 
    #_stateobject_attributes["client"] = TCPBase 


    def __repr__(self):
        return "<TCPFlow ({} messages)>".format(len(self.client.messages) + len(self.server.messages))

    def new_message(self, message: TCPMessage):
        if message.from_client:
            self.client.new_message(message)
        else:
            self.server.new_message(message)
        self.messages.append(message)

    @property 
    def raw_content(self):
        content = bytes() 
        for message in self.messages:
            content += message.content
        return content

    @property
    def timestamp(self):
        if len(self.messages) > 0:
            return self.messages[-1].timestamp
        else:
            return time.time()
