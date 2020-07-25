package com.intelligt.modbus.jlibmodbus.data;

import java.util.Arrays;

/*
 * Copyright (C) 2016 "Invertor" Factory", JSC
 * [http://www.sbp-invertor.ru]
 *
 * This file is part of JLibModbus.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Authors: Vladislav Y. Kochedykov, software engineer.
 * email: vladislav.kochedykov@gmail.com
 */
public class SimpleSlaveId implements SlaveId {

    byte slaveId;
    byte runIndicatorStatus;
    private byte[] bytes = null;

    public SimpleSlaveId(byte slaveId, byte runIndicatorStatus, int size) {
        this.slaveId = slaveId;
        this.runIndicatorStatus = runIndicatorStatus;
        this.bytes = new byte[size];
    }

    @Override
    synchronized public byte[] get() {
        byte[] info = new byte[this.bytes.length + 2];

        info[0] = slaveId;
        info[1] = runIndicatorStatus;
        System.arraycopy(this.bytes, 0, info, 2, this.bytes.length);

        return info;
    }

    @Override
    synchronized public void set(byte[] data) {
        bytes = Arrays.copyOf(data, data.length);
    }
}
