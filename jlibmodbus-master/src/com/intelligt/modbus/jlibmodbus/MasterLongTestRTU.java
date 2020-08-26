package com.intelligt.modbus.jlibmodbus;

import com.intelligt.modbus.jlibmodbus.data.CommStatus;
import com.intelligt.modbus.jlibmodbus.exception.ModbusIOException;
import com.intelligt.modbus.jlibmodbus.master.ModbusMaster;
import com.intelligt.modbus.jlibmodbus.master.ModbusMasterFactory;
import com.intelligt.modbus.jlibmodbus.serial.SerialParameters;
import com.intelligt.modbus.jlibmodbus.serial.SerialPort;

public class MasterLongTestRTU {
    static public void main(String[] arg) {
        SerialParameters sp = new SerialParameters();
        Modbus.setLogLevel(Modbus.LogLevel.LEVEL_DEBUG);
        try {
            // you can use just string to get connection with remote slave,
            // but you can also get a list of all serial ports available at your system.
            // String[] dev_list = SerialPortList.getPortNames();
            // if there is at least one serial port at your system

            // you can choose the one of those you need
            sp.setDevice("/dev/pts/6");
            // these parameters are set by default
            sp.setBaudRate(SerialPort.BaudRate.BAUD_RATE_19200);
            sp.setDataBits(8);
            sp.setParity(SerialPort.Parity.NONE);
            sp.setStopBits(1);

            ModbusMaster m = ModbusMasterFactory.createModbusMasterRTU(sp);
            m.connect();

            int slaveId = 2;
            int offset = 0;
            int quantity = 1;

            try {
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
            } catch (RuntimeException e) {
                throw e;
            } catch (Exception e) {
                e.printStackTrace();
            } finally {
                try {
                    m.disconnect();
                } catch (ModbusIOException e1) {
                    e1.printStackTrace();
                }
            }
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
