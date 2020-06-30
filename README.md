# GPIOdaemon

## Rationale

After the GPIO sysfs was deprecated the centralized way to configure and
manipulate GPIOs was no longer the part of the system. The GPIOdaemon tries to
be a solution for this problem using the *libgpiod* library.

## Operation

First, the daemon reads the config file at startup and tries to config the GPIO
lines. After it is done, the daemon will wait for the socket connections. For example the line below represents how to set the PD21 pin to high on the gpiochip1:

    echo "gpiochip1:PD21 set" | socat - UNIX-CONNECT:/var/run/gpiodaemon.sock

and to low:

    echo "gpiochip1:PD21 reset" | socat - UNIX-CONNECT:/var/run/gpiodaemon.sock

Alternatively you can replace the PD21 with the line number (117). The server will
respond with an *OK* or a *NOK* message what depends on the outcome of the command.

With the following command you can receive the input interrupts:

    socat - UNIX-CONNECT:/var/run/gpiodaemon.sock

The response will be something like that:

    [1578840336.563998441] gpiochip1:227(button):falling

## Build

Just link with an installed *libgpiod*

    gcc -Wall -lgpiod -o gpiodaemon gpiodaemon.c

## Status

This daemon is still in an active development.

## TODOs (without priorities)

* Improve receive code quality.
* Add "group" keyword to the config. This can be useful when some programs are
using GPIOs. With an initial message the client may select from the group of
interest eg. interrupts
* Update for the newer *libgpiod*
