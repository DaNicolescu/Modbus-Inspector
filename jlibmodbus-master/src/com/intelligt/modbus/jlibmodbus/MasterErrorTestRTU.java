package com.intelligt.modbus.jlibmodbus;

import com.intelligt.modbus.jlibmodbus.data.CommStatus;
import com.intelligt.modbus.jlibmodbus.exception.ModbusIOException;
import com.intelligt.modbus.jlibmodbus.master.ModbusMaster;
import com.intelligt.modbus.jlibmodbus.master.ModbusMasterFactory;
import com.intelligt.modbus.jlibmodbus.serial.SerialParameters;
import com.intelligt.modbus.jlibmodbus.serial.SerialPort;

public class MasterErrorTestRTU {

    static public void main(String[] arg) {
        SerialParameters sp = new SerialParameters();
        Modbus.setLogLevel(Modbus.LogLevel.LEVEL_DEBUG);
        try {
            // you can use just string to get connection with remote slave,
            // but you can also get a list of all serial ports available at your system.
            // String[] dev_list = SerialPortList.getPortNames();
            // if there is at least one serial port at your system

            // you can choose the one of those you need
            sp.setDevice("/dev/pts/5");
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
                int[] registerValues = m.readHoldingRegisters(slaveId, 20, 3);

                for (int value : registerValues) {
                    System.out.println("Address: " + offset++ + ", Value: " + value);
                }

                offset = 0;

                // read input registers
                int[] inputRegisterValues = m.readInputRegisters(slaveId, offset, 2);

                for (int value : inputRegisterValues) {
                    System.out.println("Address: " + offset++ + ", Value: " + value);
                }

                offset = 0;

                // read coils
                boolean[] coilValues = m.readCoils(slaveId, offset, 4);

                for (boolean value : coilValues) {
                    System.out.println("Address: " + offset++ + ", Value: " + value);
                }

                offset = 0;

                // read discrete inputs
                boolean[] discreteInputsValues = m.readDiscreteInputs(slaveId, offset, 6);

                for (boolean value : discreteInputsValues) {
                    System.out.println("Address: " + offset++ + ", Value: " + value);
                }

                // write single coil
                m.writeSingleCoil(slaveId, 10, true);

                // write single register
                m.writeSingleRegister(slaveId, 50, 25);

                // write multiple coils
                m.writeMultipleCoils(slaveId, 12, new boolean[]{false, true});

                // write multiple registers
                m.writeMultipleRegisters(slaveId, 40, new int[]{10, 11});

                // read exception status
                int excetptionStatus = m.readExceptionStatus(slaveId);

                System.out.println("exception: " + excetptionStatus);

                // report slave id
                byte[] slaveIdInfo = m.reportSlaveId(slaveId);

                System.out.println("Slave ID message length:" + slaveIdInfo.length);

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
