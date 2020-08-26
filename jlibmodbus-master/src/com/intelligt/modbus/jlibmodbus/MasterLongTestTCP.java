package com.intelligt.modbus.jlibmodbus;

import com.intelligt.modbus.jlibmodbus.exception.ModbusIOException;
import com.intelligt.modbus.jlibmodbus.exception.ModbusNumberException;
import com.intelligt.modbus.jlibmodbus.exception.ModbusProtocolException;
import com.intelligt.modbus.jlibmodbus.master.ModbusMaster;
import com.intelligt.modbus.jlibmodbus.master.ModbusMasterFactory;
import com.intelligt.modbus.jlibmodbus.tcp.TcpParameters;

import java.net.InetAddress;

public class MasterLongTestTCP {
    static public void main(String[] args) {
        try {
            TcpParameters tcpParameters = new TcpParameters();

            //tcp parameters have already set by default as in example
            tcpParameters.setHost(InetAddress.getLocalHost());
            tcpParameters.setKeepAlive(true);
            tcpParameters.setPort(Modbus.TCP_PORT);

            //if you would like to set connection parameters separately,
            // you should use another method: createModbusMasterTCP(String host, int port, boolean keepAlive);
            ModbusMaster m = ModbusMasterFactory.createModbusMasterTCP(tcpParameters);
            Modbus.setAutoIncrementTransactionId(true);

            int slaveId = 2;
            int offset = 0;

            try {
                // since 1.2.8
                if (!m.isConnected()) {
                    m.connect();
                }

                // read holding registers
                for (int i = 0; i < 100; i++) {
                    int[] registerValues = m.readHoldingRegisters(slaveId, offset, 4);
                    Thread.sleep(100);
                }

                // read input registers
                for (int i = 0; i < 100; i++) {
                    int[] inputRegisterValues = m.readInputRegisters(slaveId, offset, 4);
                    Thread.sleep(100);
                }

                // read coils
                for (int i = 0; i < 100; i++) {
                    boolean[] coilValues = m.readCoils(slaveId, offset, 6);
                    Thread.sleep(100);
                }

                // write single coil
                for (int i = 0; i < 100; i++) {
                    m.writeSingleCoil(slaveId, 10, true);
                    Thread.sleep(100);
                }

                // write single register
                for (int i = 0; i < 100; i++) {
                    m.writeSingleRegister(slaveId, 2, 25);
                    Thread.sleep(100);
                }
            } catch (ModbusProtocolException e) {
                e.printStackTrace();
            } catch (ModbusNumberException e) {
                e.printStackTrace();
            } catch (ModbusIOException e) {
                e.printStackTrace();
            } finally {
                try {
                    m.disconnect();
                } catch (ModbusIOException e) {
                    e.printStackTrace();
                }
            }
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
