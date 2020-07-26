package com.intelligt.modbus.jlibmodbus;

import com.intelligt.modbus.jlibmodbus.data.DataHolder;
import com.intelligt.modbus.jlibmodbus.data.ModbusCoils;
import com.intelligt.modbus.jlibmodbus.data.ModbusHoldingRegisters;
import com.intelligt.modbus.jlibmodbus.exception.IllegalDataAddressException;
import com.intelligt.modbus.jlibmodbus.exception.IllegalDataValueException;
import com.intelligt.modbus.jlibmodbus.slave.ModbusSlave;
import com.intelligt.modbus.jlibmodbus.slave.ModbusSlaveFactory;
import com.intelligt.modbus.jlibmodbus.tcp.TcpParameters;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;

public class SlaveTest2TCP {

    static public void main(String[] argv) {

        try {

            final ModbusSlave slave;

            TcpParameters tcpParameters = new TcpParameters();

            tcpParameters.setHost(InetAddress.getLocalHost());
            tcpParameters.setKeepAlive(true);
            tcpParameters.setPort(Modbus.TCP_PORT);

            slave = ModbusSlaveFactory.createModbusSlaveTCP(tcpParameters);
            Modbus.setLogLevel(Modbus.LogLevel.LEVEL_DEBUG);

            SlaveTestTCP.MyOwnDataHolder dh = new SlaveTestTCP.MyOwnDataHolder();
            dh.addEventListener(new SlaveTestTCP.ModbusEventListener() {
                @Override
                public void onWriteToSingleCoil(int address, boolean value) {
                    System.out.print("onWriteToSingleCoil: address " + address + ", value " + value);
                }

                @Override
                public void onWriteToMultipleCoils(int address, int quantity, boolean[] values) {
                    System.out.print("onWriteToMultipleCoils: address " + address + ", quantity " + quantity);
                }

                @Override
                public void onWriteToSingleHoldingRegister(int address, int value) {
                    System.out.print("onWriteToSingleHoldingRegister: address " + address + ", value " + value);
                }

                @Override
                public void onWriteToMultipleHoldingRegisters(int address, int quantity, int[] values) {
                    System.out.print("onWriteToMultipleHoldingRegisters: address " + address + ", quantity " + quantity);
                }
            });

            slave.setDataHolder(dh);

            // set holding registers
            ModbusHoldingRegisters hr = new ModbusHoldingRegisters(250);
            hr.set(0, 1);
            hr.set(1, 1);
            hr.set(2, 0);
            hr.set(3, 1);
            hr.set(4, 2);
            slave.getDataHolder().setHoldingRegisters(hr);

            slave.setServerAddress(3);
            /*
             * using master-branch it should be #slave.open();
             */
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
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public interface ModbusEventListener {
        void onWriteToSingleCoil(int address, boolean value);

        void onWriteToMultipleCoils(int address, int quantity, boolean[] values);

        void onWriteToSingleHoldingRegister(int address, int value);

        void onWriteToMultipleHoldingRegisters(int address, int quantity, int[] values);
    }

    public static class MyOwnDataHolder extends DataHolder {

        final List<SlaveTestTCP.ModbusEventListener> modbusEventListenerList = new ArrayList<SlaveTestTCP.ModbusEventListener>();

        public MyOwnDataHolder() {
            // you can place the initialization code here
            /*
            something like that:
            setHoldingRegisters(new SimpleHoldingRegisters(10));
            setCoils(new Coils(128));
            ...
            etc.
             */
        }

        public void addEventListener(SlaveTestTCP.ModbusEventListener listener) {
            modbusEventListenerList.add(listener);
        }

        public boolean removeEventListener(SlaveTestTCP.ModbusEventListener listener) {
            return modbusEventListenerList.remove(listener);
        }

        @Override
        public void writeHoldingRegister(int offset, int value) throws IllegalDataAddressException, IllegalDataValueException {
            for (SlaveTestTCP.ModbusEventListener l : modbusEventListenerList) {
                l.onWriteToSingleHoldingRegister(offset, value);
            }
            super.writeHoldingRegister(offset, value);
        }

        @Override
        public void writeHoldingRegisterRange(int offset, int[] range) throws IllegalDataAddressException, IllegalDataValueException {
            for (SlaveTestTCP.ModbusEventListener l : modbusEventListenerList) {
                l.onWriteToMultipleHoldingRegisters(offset, range.length, range);
            }
            super.writeHoldingRegisterRange(offset, range);
        }

        @Override
        public void writeCoil(int offset, boolean value) throws IllegalDataAddressException, IllegalDataValueException {
            for (SlaveTestTCP.ModbusEventListener l : modbusEventListenerList) {
                l.onWriteToSingleCoil(offset, value);
            }
            super.writeCoil(offset, value);
        }

        @Override
        public void writeCoilRange(int offset, boolean[] range) throws IllegalDataAddressException, IllegalDataValueException {
            for (SlaveTestTCP.ModbusEventListener l : modbusEventListenerList) {
                l.onWriteToMultipleCoils(offset, range.length, range);
            }
            super.writeCoilRange(offset, range);
        }
    }
}
