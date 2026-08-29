from pymodbus.datastore import (ModbusSequentialDataBlock, ModbusSlaveContext,
                                ModbusServerContext)
from pymodbus.server import StartTcpServer

# Writable coils (0/1) and holding registers - no auth layer exists in Modbus.
store = ModbusSlaveContext(
    co=ModbusSequentialDataBlock(0, [0] * 100),
    hr=ModbusSequentialDataBlock(0, [17] * 100),
    di=ModbusSequentialDataBlock(0, [1] * 100),
    ir=ModbusSequentialDataBlock(0, [42] * 100),
)
context = ModbusServerContext(slaves=store, single=True)
print('Modbus/TCP PLC listening on 0.0.0.0:502 (no auth, writable)')
StartTcpServer(context, address=('0.0.0.0', 502))
