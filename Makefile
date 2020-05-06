# SPDX-License-Identifier: MIT
# Jeff R. Stripling
#
# A simple makefile for my sha256 project.
#
# Usage:
#
#  make - build the target
#  make clean - remove any created files
#  make depend - update header file dependancies
 
CC = gcc
CFLAGS = -Wall
RM = rm

SRC = sha256.c main.c
INC = sha256.h

OBJ = $(SRC:.c=.o)

sha256: $(OBJ)
	$(CC) -o $@ $^

$(OBJ): %.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $<

.PHONY: clean depend

clean:
	$(RM) $(OBJ) .depend sha256
	
depend: .depend

.depend: $(SRC) $(INC)
	$(CC) $(CFLAGS) -MM $^ > $@
	
-include .depend
