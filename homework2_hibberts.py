# TO RUN: sudo python homework2_hibberts.py


# Sources used:
# proc(5) - Linux manual page, https://man7.org/linux/man-pages/man5/proc.5.html
# Process list on Linux via Python, https://stackoverflow.com/questions/2703640/process-list-on-linux-via-python
# Exploring /proc File System in Linux, https://www.tecmint.com/exploring-proc-file-system-in-linux/
# Python | os.listdir() method, https://www.geeksforgeeks.org/python-os-listdir-method/
# Python String ljust() Method, https://www.tutorialspoint.com/python/string_ljust.htm
# Simple Text Menu in Python, https://extr3metech.wordpress.com/2014/09/14/simple-text-menu-in-python/
# How do I read from /proc/$pid/mem under Linux?, https://unix.stackexchange.com/questions/6301/how-do-i-read-from-proc-pid-mem-under-linux
# Python int(), https://www.programiz.com/python-programming/methods/built-in/int

import os
import sys


def one():
# 1. Enumerate all the running processes
	
	# list the processes in the /proc filesystem and return all processes which
	# have a process id (pid)
	processes = [pid for pid in os.listdir('/proc') if pid.isdigit()]

	print '\n'
	print "1. Enumerate all the running processes"
	print '\n'
	
	# print column headers
	print "Name   ".ljust(30), "PID".ljust(10), "State".ljust(30) 

	# retrieve all the process names, states and pids
	for pid in processes:
		info = open(os.path.join('/proc', pid, 'status'), mode='rb').read().split('\n')
		name = info[0]
		state = info[2]

		# only print the running processes
		if "running" in state:
			print name[6:].ljust(30), pid.ljust(10), state[7:].ljust(30)
		else:
			continue	

	# return to the menu	
	menu()
	 	
def two():
# 2. List all the running threads within process boundary

	print '\n'
	print "2. List all the running threads within a process"
	print '\n'

	# ask user which pid they would like to view the threads for
	choicePid = raw_input("Please enter PID to view its threads: ")
	print '\n'

	# check the user entered a number and re-prompt if not
	while not choicePid.isdigit():
		choicePid = raw_input("Please enter PID to view its loaded modules: ")
		print '\n'

	# print column titles
	print "Thread Name".ljust(30), "TID".ljust(10), "PID".ljust(10), "Parent Process".ljust(30), "PPID".ljust(10),"State".ljust(10)

	# retrieve information about the user's specified pid
	info = open(os.path.join('/proc', choicePid, 'status'), mode='rb').read().split('\n')
	name = info[0]
		
	# open the task subdirectory which contains subdirectories for each thread used by the process
	threadIDs = os.path.join('/proc', choicePid, 'task')

	# open each thread subdirectory and display its name, thread id, pid, parent name, parent pid and current state	
	for direc in os.listdir(threadIDs):
		threadInfo = open(os.path.join(threadIDs, direc, 'status'), mode='rb').read().split('\n')
		threadState = threadInfo[2]
		threadName = threadInfo[0]
		tid = threadInfo[3]
		pid = threadInfo[5]
		ppid = threadInfo[6]

		# only print the running threads
		if "running" in threadState:
			print threadName[6:].ljust(30), tid[6:].ljust(10), pid[5:].ljust(10), name[6:].ljust(30), ppid[6:].ljust(10), threadState[7:].ljust(10)
		else:
			continue	
	# return to the menu	
	menu()

def three():
# 3. Enumerate all the loaded modules within the processes

	print '\n'
	print "3. Enumerate all the loaded modules within a process"
	print '\n'

	# ask user which pid they would like to view the loaded modules for
	choicePid = raw_input("Please enter PID to view its loaded modules: ")
	print '\n'

	# check the user entered a number and re-prompt if not
	while not choicePid.isdigit():
		choicePid = raw_input("Please enter PID to view its loaded modules: ")
		print '\n'

	# get information about the user's specified pid
	info = open(os.path.join('/proc', choicePid, 'status'), mode='rb').read().split('\n')
	name = info[0]

	print "Loaded Modules for Process Name:", name[6:], "- PID:", choicePid

	# /proc/pid/maps contains the loaded modules or shared objects for the process
	modList = open(os.path.join('/proc', choicePid, 'maps'), mode='rb').read()

	lines = modList.split('\n')

	for line in lines:
		if line:
			splitLine = line.split(' ')

			# if there is a module pathname listed (which is the last entry of the list), print it
			if splitLine[-1]:
				print splitLine[-1]

	# return to the menu	
	menu()

def four():	
# 4. Is able to show all the executable pages within the processes

	print '\n'
	print "4. Show all the executable pages within a process"
	print '\n'

	# ask user which pid they would like to view the threads for
	choicePid = raw_input("Please enter PID to view its executable pages: ")
	print '\n'
	
	# check the user entered a number and re-prompt if not
	while not choicePid.isdigit():
		choicePid = raw_input("Please enter PID to view its loaded modules: ")
		print '\n'

	# get information about the user's specified pid
	info = open(os.path.join('/proc', choicePid, 'status'), mode='rb').read().split('\n')
	name = info[0]

	# /proc/pid/maps contains the currently mapped memory regions for the process and
	# their access permissions
	maps = open(os.path.join('/proc', choicePid, 'maps'), mode='rb').read()
	lines = maps.split('\n')

	print "Executable pages for Process Name:", name[6:], "- PID: ", choicePid

	for line in lines:

		# if the memory mapped region has executable permissions, display the pathname
		if line:
			splitLine = line.split(' ')
			if len(splitLine) > 24 and "x" in splitLine[1]:
				if splitLine[24]:
					print splitLine[24]
	# return to the menu	
	menu()				

def five():
# 5. Gives us a capability to read the memory

	print '\n'
	print "5. Read memory within a process"
	
	print '\n'
	# ask user which pid they would like to view the threads for
	choicePid = raw_input("Please enter PID to view readable memory addresses: ")
	print '\n'

	# check the user entered a number and re-prompt if not
	while not choicePid.isdigit():
		choicePid = raw_input("Please enter PID to view its loaded modules: ")
		print '\n'
	
	# get information about the user's specified pid
	info = open(os.path.join('/proc', choicePid, 'status'), mode='rb').read().split('\n')
	name = info[0]
		
	# map the memory regions for the process and their access permissions
	maps = open(os.path.join('/proc', choicePid, 'maps'), mode='rb').read()
	mapLines = maps.split('\n')

	#  open the memory file for the process
	procMem = open(os.path.join('/proc', choicePid, 'mem'), mode='rb')

	# find out which parts of the process memory are mapped to read
	for line in mapLines:
		if line:
			splitLine = line.split(' ')

			# if we find a readable region
			if "r" in splitLine[1]:

				# retrieve the name of the readable region (at the end of the list)
				memName = splitLine[-1]
				address1 = splitLine[0].split('-')
		
				# find the address of the start of the region
				start = address1[0]

				# find the address of the end of the region
				end = address1[1]

				# if there is a name associated with the readable region	
				if memName:
					# display the readable address regions to the user
					print "Readable memory regions for Process Name:", name[6:], "- PID:", choicePid
					print "Name: ", memName
					print "Start: ", start
					print "End: ", end
					print '\n'

	# ask user to specify the start and end of readable memory addresses they want to view
	choiceStart = raw_input("Please choose a start address from above: ")

	choiceEnd = raw_input("Please enter the corresponding end address: ")

	# convert hex address to int
	hexStart = int(choiceStart, 16)
	hexEnd = int(choiceEnd, 16)

	# point the memory file to the start address
	procMem.seek(hexStart)

	# work out the number of bytes to read from the memory file
	readBytes = hexEnd - hexStart

	#read the contents of the memory region
	memContent = procMem.read(readBytes)
	
	print '\n'
	print "The memory contents at this address are as follows:"
	print '\n'
	print memContent

	# return to the menu	
	menu()

def menu():
	print '\n'
	print "**************************************"
	print "1. Enumerate all the running processes"
	print "2. List all the running threads within a process"
	print "3. Enumerate all the loaded modules within a process"
	print "4. Show all the executable pages within a process"
	print "5. Read memory within a process"
	print "6. Quit"
	print '\n'

	choice = raw_input("Please enter your choice [1-6]: ")
	if choice == "1":
		one()
	elif choice == "2":
		two()
	elif choice == "3":
		three()
	elif choice == "4":
		four()
	elif choice == "5":
		five()
	elif choice == "6":
		exit()
	else:
		print("Please select an option from 1 to 6")
    	menu()


def main():
	print '\n'
	print "**********     HOMEWORK 2     **********"
	print "**********  by Susan Hibbert  **********"

	menu()

if __name__ == '__main__':
	main()
