# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: msg_begin_redelegate.proto
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


import interfaces.gogo_pb2 as gogo__pb2
import interfaces.coin_pb2 as coin__pb2


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x1amsg_begin_redelegate.proto\x12\x16\x63osmos.staking.v1beta1\x1a\ngogo.proto\x1a\ncoin.proto\"\x8a\x02\n\x12MsgBeginRedelegate\x12\x37\n\x11\x64\x65legator_address\x18\x01 \x01(\tB\x1c\xf2\xde\x1f\x18yaml:\"delegator_address\"\x12?\n\x15validator_src_address\x18\x02 \x01(\tB \xf2\xde\x1f\x1cyaml:\"validator_src_address\"\x12?\n\x15validator_dst_address\x18\x03 \x01(\tB \xf2\xde\x1f\x1cyaml:\"validator_dst_address\"\x12/\n\x06\x61mount\x18\x04 \x01(\x0b\x32\x19.cosmos.base.v1beta1.CoinB\x04\xc8\xde\x1f\x00:\x08\xe8\xa0\x1f\x00\x88\xa0\x1f\x00\x42.Z,github.com/cosmos/cosmos-sdk/x/staking/typesb\x06proto3')



_MSGBEGINREDELEGATE = DESCRIPTOR.message_types_by_name['MsgBeginRedelegate']
MsgBeginRedelegate = _reflection.GeneratedProtocolMessageType('MsgBeginRedelegate', (_message.Message,), {
  'DESCRIPTOR' : _MSGBEGINREDELEGATE,
  '__module__' : 'msg_begin_redelegate_pb2'
  # @@protoc_insertion_point(class_scope:cosmos.staking.v1beta1.MsgBeginRedelegate)
  })
_sym_db.RegisterMessage(MsgBeginRedelegate)

if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  DESCRIPTOR._serialized_options = b'Z,github.com/cosmos/cosmos-sdk/x/staking/types'
  _MSGBEGINREDELEGATE.fields_by_name['delegator_address']._options = None
  _MSGBEGINREDELEGATE.fields_by_name['delegator_address']._serialized_options = b'\362\336\037\030yaml:\"delegator_address\"'
  _MSGBEGINREDELEGATE.fields_by_name['validator_src_address']._options = None
  _MSGBEGINREDELEGATE.fields_by_name['validator_src_address']._serialized_options = b'\362\336\037\034yaml:\"validator_src_address\"'
  _MSGBEGINREDELEGATE.fields_by_name['validator_dst_address']._options = None
  _MSGBEGINREDELEGATE.fields_by_name['validator_dst_address']._serialized_options = b'\362\336\037\034yaml:\"validator_dst_address\"'
  _MSGBEGINREDELEGATE.fields_by_name['amount']._options = None
  _MSGBEGINREDELEGATE.fields_by_name['amount']._serialized_options = b'\310\336\037\000'
  _MSGBEGINREDELEGATE._options = None
  _MSGBEGINREDELEGATE._serialized_options = b'\350\240\037\000\210\240\037\000'
  _MSGBEGINREDELEGATE._serialized_start=79
  _MSGBEGINREDELEGATE._serialized_end=345
# @@protoc_insertion_point(module_scope)
