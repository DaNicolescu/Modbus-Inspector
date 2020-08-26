package com.intelligt.modbus.jlibmodbus;

import com.intelligt.modbus.jlibmodbus.Modbus;
import com.intelligt.modbus.jlibmodbus.data.CommStatus;
import com.intelligt.modbus.jlibmodbus.master.ModbusMaster;
import com.intelligt.modbus.jlibmodbus.master.ModbusMasterFactory;
import com.intelligt.modbus.jlibmodbus.exception.ModbusIOException;
import com.intelligt.modbus.jlibmodbus.serial.SerialParameters;
import com.intelligt.modbus.jlibmodbus.serial.SerialPort;
import com.intelligt.modbus.jlibmodbus.serial.SerialPortFactoryJSSC;
import com.intelligt.modbus.jlibmodbus.serial.SerialUtils;
import jssc.SerialPortList;

/*
 * Copyright (C) 2016 "Invertor" Factory", JSC
 * All rights reserved
 *
 * This file is part of JLibModbus.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation and/or
 * other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Authors: Vladislav Y. Kochedykov, software engineer.
 * email: vladislav.kochedykov@gmail.com
 */
public class MasterTestRTU {

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
                int[] registerValues = m.readHoldingRegisters(slaveId, offset, quantity);

                for (int value : registerValues) {
                    System.out.println("Address: " + offset++ + ", Value: " + value);
                }

                offset = 0;

                // read input registers
                int[] inputRegisterValues = m.readInputRegisters(slaveId, offset, 4);

                for (int value : inputRegisterValues) {
                    System.out.println("Address: " + offset++ + ", Value: " + value);
                }

                offset = 0;

                // read coils
                boolean[] coilValues = m.readCoils(slaveId, offset, 6);

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
                m.writeSingleRegister(slaveId, 2, 25);

                // write multiple coils
                m.writeMultipleCoils(slaveId, 1, new boolean[]{true, false, true});

                // write multiple registers
                m.writeMultipleRegisters(slaveId, 1, new int[]{10, 11});

                // mask write register
                m.maskWriteRegister(slaveId, 3, 242, 37);

                // read exception status
                int excetptionStatus = m.readExceptionStatus(slaveId);

                System.out.println("exception: " + excetptionStatus);

                // report slave id
                byte[] slaveIdInfo = m.reportSlaveId(slaveId);

                System.out.println("Slave ID message length:" + slaveIdInfo.length);

                CommStatus commStatus = m.getCommEventCounter(slaveId);

                System.out.println("Comm event counter: " + commStatus.toString());

                CommStatus commLog = m.getCommEventLog(slaveId);

                System.out.println("Comm event log: " + commLog.toString());

                m.diagnosticsReturnQueryData(slaveId, 25);

                int diagRegister = m.diagnosticsReturnDiagnosticRegister(slaveId);

                System.out.println("diag register: " + diagRegister);

                int busMessageCount = m.diagnosticsReturnBusMessageCount(slaveId);

                System.out.println("bus message count: " + busMessageCount);

                int busErrorCount =  m.diagnosticsReturnBusCommunicationErrorCount(slaveId);

                System.out.println("bus error count: " + busErrorCount);

                m.diagnosticsReturnBusExceptionErrorCount(slaveId);

                m.diagnosticsReturnSlaveMessageCount(slaveId);

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
