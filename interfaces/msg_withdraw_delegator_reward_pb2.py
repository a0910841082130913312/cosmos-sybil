# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: msg_withdraw_delegator_reward.proto
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


import interfaces.gogo_pb2 as gogo__pb2


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n#msg_withdraw_delegator_reward.proto\x12\x1b\x63osmos.distribution.v1beta1\x1a\ngogo.proto\"\x98\x01\n\x1aMsgWithdrawDelegatorReward\x12\x37\n\x11\x64\x65legator_address\x18\x01 \x01(\tB\x1c\xf2\xde\x1f\x18yaml:\"delegator_address\"\x12\x37\n\x11validator_address\x18\x02 \x01(\tB\x1c\xf2\xde\x1f\x18yaml:\"validator_address\":\x08\xe8\xa0\x1f\x00\x88\xa0\x1f\x00\x42\x33Z1github.com/cosmos/cosmos-sdk/x/distribution/typesb\x06proto3')



_MSGWITHDRAWDELEGATORREWARD = DESCRIPTOR.message_types_by_name['MsgWithdrawDelegatorReward']
MsgWithdrawDelegatorReward = _reflection.GeneratedProtocolMessageType('MsgWithdrawDelegatorReward', (_message.Message,), {
  'DESCRIPTOR' : _MSGWITHDRAWDELEGATORREWARD,
  '__module__' : 'msg_withdraw_delegator_reward_pb2'
  # @@protoc_insertion_point(class_scope:cosmos.distribution.v1beta1.MsgWithdrawDelegatorReward)
  })
_sym_db.RegisterMessage(MsgWithdrawDelegatorReward)

if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  DESCRIPTOR._serialized_options = b'Z1github.com/cosmos/cosmos-sdk/x/distribution/types'
  _MSGWITHDRAWDELEGATORREWARD.fields_by_name['delegator_address']._options = None
  _MSGWITHDRAWDELEGATORREWARD.fields_by_name['delegator_address']._serialized_options = b'\362\336\037\030yaml:\"delegator_address\"'
  _MSGWITHDRAWDELEGATORREWARD.fields_by_name['validator_address']._options = None
  _MSGWITHDRAWDELEGATORREWARD.fields_by_name['validator_address']._serialized_options = b'\362\336\037\030yaml:\"validator_address\"'
  _MSGWITHDRAWDELEGATORREWARD._options = None
  _MSGWITHDRAWDELEGATORREWARD._serialized_options = b'\350\240\037\000\210\240\037\000'
  _MSGWITHDRAWDELEGATORREWARD._serialized_start=81
  _MSGWITHDRAWDELEGATORREWARD._serialized_end=233
# @@protoc_insertion_point(module_scope)
