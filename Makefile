build:
	gcc btguard.c -o btguard -ldl
	gcc -fPIC -shared -o btguard.so btguard.c -ldl
clean:
	rm -rf btguard btguard.so 
	rm *.log *.txt
	
