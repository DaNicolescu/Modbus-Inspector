package com.intelligt.modbus.jlibmodbus;

import com.intelligt.modbus.jlibmodbus.data.*;
import com.intelligt.modbus.jlibmodbus.data.comm.ModbusCommEventSend;
import com.intelligt.modbus.jlibmodbus.exception.ModbusIOException;
import com.intelligt.modbus.jlibmodbus.exception.ModbusNumberException;
import com.intelligt.modbus.jlibmodbus.exception.ModbusProtocolException;
import com.intelligt.modbus.jlibmodbus.serial.*;
import com.intelligt.modbus.jlibmodbus.slave.ModbusSlave;
import com.intelligt.modbus.jlibmodbus.slave.ModbusSlaveFactory;
import com.intelligt.modbus.jlibmodbus.utils.DataUtils;
import com.intelligt.modbus.jlibmodbus.utils.FrameEvent;
import com.intelligt.modbus.jlibmodbus.utils.FrameEventListener;

import java.nio.charset.Charset;

public class SlaveTestRTU {
    final static private int slaveId = 2;

    public static void main(String[] argv) {
        try {
            Modbus.setLogLevel(Modbus.LogLevel.LEVEL_DEBUG);
            SerialParameters serialParameters = new SerialParameters();

            serialParameters.setDevice("/dev/pts/6");
            // these parameters are set by default
            serialParameters.setBaudRate(SerialPort.BaudRate.BAUD_RATE_19200);
            serialParameters.setDataBits(8);
            serialParameters.setParity(SerialPort.Parity.NONE);
            serialParameters.setStopBits(1);

            SerialUtils.setSerialPortFactory(new SerialPortFactoryJSSC());
            ModbusSlave slave = ModbusSlaveFactory.createModbusSlaveRTU(serialParameters);

            slave.setServerAddress(slaveId);
            slave.setBroadcastEnabled(true);
            slave.setReadTimeout(5000);

            FrameEventListener listener = new FrameEventListener() {
                @Override
                public void frameSentEvent(FrameEvent event) {
                    System.out.println("frame sent " + DataUtils.toAscii(event.getBytes()));
                }

                @Override
                public void frameReceivedEvent(FrameEvent event) {
                    System.out.println("frame recv " + DataUtils.toAscii(event.getBytes()));
                }
            };

            slave.addListener(listener);

            ModbusHoldingRegisters holdingRegisters = new ModbusHoldingRegisters(10);

            for (int i = 0; i < holdingRegisters.getQuantity(); i++) {
                //fill
                holdingRegisters.set(i, i + 1);
            }

            //place the number PI at offset 0
            holdingRegisters.setFloat64At(0, Math.PI);

            slave.getDataHolder().setHoldingRegisters(holdingRegisters);

            // set input registers
            ModbusHoldingRegisters inputRegisters = new ModbusHoldingRegisters(4);
            inputRegisters.set(0, 10);
            inputRegisters.set(1, 11);
            inputRegisters.set(2, 12);
            inputRegisters.set(3, 13);
            slave.getDataHolder().setInputRegisters(inputRegisters);

            // set read coils
            ModbusCoils coils = new ModbusCoils(15);

            coils.set(0, true);
            coils.set(1, true);
            coils.set(2, false);
            coils.set(3, true);
            coils.set(4, false);
            coils.set(5, false);
            slave.getDataHolder().setCoils(coils);

            // set discrete inputs
            ModbusCoils discreteInputs = new ModbusCoils(6);

            discreteInputs.set(0, true);
            discreteInputs.set(1, false);
            discreteInputs.set(2, false);
            discreteInputs.set(3, false);
            discreteInputs.set(4, false);
            discreteInputs.set(5, false);
            slave.getDataHolder().setDiscreteInputs(discreteInputs);

            SlaveId slaveId = new SimpleSlaveId((byte)2, (byte)255, 33);
            ExceptionStatus exceptionStatus = new SimpleExceptionStatus(123);

            slaveId.set("slave implementation = jlibmodbus".getBytes(Charset.forName("UTF-8")));

            slave.getDataHolder().setSlaveId(slaveId);
            slave.getDataHolder().setExceptionStatus(exceptionStatus);

            // slave.getDataHolder().getSlaveId().set("slave implementation = jlibmodbus".getBytes(Charset.forName("UTF-8")));
            // slave.getDataHolder().getExceptionStatus().set(123);
            slave.getDataHolder().getCommStatus().addEvent(ModbusCommEventSend.createExceptionSentRead());

            slave.listen();

            /*
             * since 1.2.8
             */
            if (slave.isListening()) {
                Runtime.getRuntime().addShutdownHook(new Thread() {
                    @Override
                    public void run() {
                        synchronized (slave) {
                            slave.notifyAll();
                        }
                    }
                });

                synchronized (slave) {
                    slave.wait();
                }

                /*
                 * using master-branch it should be #slave.close();
                 */
                slave.shutdown();
            }

            slave.shutdown();
        } catch (ModbusProtocolException e) {
            e.printStackTrace();
        } catch (ModbusIOException e) {
            e.printStackTrace();
        } catch (SerialPortException e) {
            e.printStackTrace();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }
}
