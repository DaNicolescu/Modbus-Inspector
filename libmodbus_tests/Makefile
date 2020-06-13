random-server: random-test-server.c
	gcc random-test-server.c -o random-test-server -lmodbus -I/usr/include/modbus

random-client: random-test-client.c
	gcc random-test-client.c -o random-test-client -lmodbus -I/usr/include/modbus

master-sim: master_sim.c
	gcc master_sim.c -o master_sim -lmodbus -I/usr/include/modbus

slave-sim: slave_sim.c
	gcc slave_sim.c -o slave_sim -lmodbus -I/usr/include/modbus
