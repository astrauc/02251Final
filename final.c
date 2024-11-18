#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#define INSTRUCTION_SIZE 4

int main(int argc, char *argv[]){

	/* get the filename to be opened*/
	if (argc != 2){
		printf("Usage: ./final [INPUT FILE PATH]\n");
		return 1;
	}
	char filename[1024];
	strcpy(filename, argv[argc - 1]);
	
	/* get the file input*/
	FILE *input = NULL;
	input = fopen(filename, "rb");
	if (input == NULL){
		perror("file open failed");
		return 1;
	}

	fseek(input, 0L, SEEK_END);
	long int filesize = ftell(input);
	/* go back to start file for processing*/
	rewind(input);

	/* total file size divided by 4 bytes per instruction*/
	size_t array_size = filesize/INSTRUCTION_SIZE;
	uint32_t *instructions = malloc(array_size);

	size_t numIntegers = filesize / sizeof(uint32_t);

    // Allocate memory to hold the file's contents as an array of uint32_t
    if (instructions == NULL) {
        perror("Memory allocation failed");
        fclose(input);
        return 1;
    }

    // Read the contents of the file into the array
    size_t readCount = fread(instructions, sizeof(uint32_t), numIntegers, input);
    if (readCount != numIntegers) {
        perror("Error reading file");
        free(instructions);
        fclose(input);
        return 1;
    }

    // Now array holds the 32-bit integer contents of the file
    printf("Successfully read %zu 32-bit integers from the file.\n", readCount);

    // Close the file and free the memory
    fclose(input);
	printf("eeee");
    int i = 0;
	for (i = 0; i < array_size; i++){
		printf("Instruction number %d: %u\n", i + 1, instructions[i]);
	}
	
	
	int instr;
	int opcode;
	int rd;
	int rs1;
	int imm;

	printf("hello\n");
	fclose(input);

}
