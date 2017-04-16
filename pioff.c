#define _GNU_SOURCE
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <wiringPi.h>

/*===========================================================================*/
int main()
{
if(wiringPiSetup() == -1)
	{
	puts ("wiringPi failed!");
	system("poweroff");
	}

pinMode(0, OUTPUT);
pinMode(7, INPUT);

while(1)
	{
	digitalWrite(0, HIGH);
	delay (25);
	digitalWrite(0, LOW);
	delay (25);
	if(digitalRead(7) == 1)
		{
		digitalWrite(0, HIGH);
		system("poweroff");
		}
	sleep(5);
	}

return EXIT_SUCCESS;
}
/*===========================================================================*/
