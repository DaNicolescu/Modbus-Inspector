all: master-sim slave-sim

master-sim: master_sim.c
	gcc master_sim.c -o master_sim -lmodbus -I/usr/include/modbus

slave-sim: slave_sim.c
	gcc slave_sim.c -o slave_sim -lmodbus -I/usr/include/modbus

clean:
	rm master_sim slave_sim
