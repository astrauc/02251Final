#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <dirent.h>
#include <assert.h>

#define FUNCT3_ADD   0b000
#define FUNCT3_SUB   0b000
#define FUNCT3_ADDI  0b000
#define FUNCT3_SYSTEM 0b000
#define FUNCT3_SLL   0b001
#define FUNCT3_SLLI  0b001
#define FUNCT3_SLT   0b010
#define FUNCT3_SLTI  0b010
#define FUNCT3_SLTU  0b011
#define FUNCT3_SLTIU 0b011
#define FUNCT3_XOR   0b100
#define FUNCT3_XORI  0b100
#define FUNCT3_SRL   0b101
#define FUNCT3_SRLI  0b101
#define FUNCT3_SRA   0b101
#define FUNCT3_SRAI  0b101
#define FUNCT3_OR    0b110
#define FUNCT3_ORI   0b110
#define FUNCT3_AND   0b111
#define FUNCT3_ANDI  0b111

// Branches
#define FUNCT3_BEQ   0b000
#define FUNCT3_BNE   0b001
#define FUNCT3_BLT   0b100
#define FUNCT3_BGE   0b101
#define FUNCT3_BLTU  0b110
#define FUNCT3_BGEU  0b111

// Load and Store
#define FUNCT3_LB    0b000
#define FUNCT3_SB    0b000
#define FUNCT3_LH    0b001
#define FUNCT3_SH    0b001
#define FUNCT3_LW    0b010
#define FUNCT3_SW    0b010
#define FUNCT3_LBU   0b100
#define FUNCT3_LHU   0b101

// Funct7 constants
#define FUNCT7_DEFAULT      0b0000000
#define FUNCT7_ALTERNATIVE  0b0100000

typedef enum {
    LUI    = 0b0110111,
    AUIPC  = 0b0010111,
    JAL    = 0b1101111,
    JALR   = 0b1100111,
    BRANCH = 0b1100011,
    LOAD   = 0b0000011,
    STORE  = 0b0100011,
    IMM    = 0b0010011,
    ARITH  = 0b0110011,
    FENCE  = 0b0001111,
    SYSTEM = 0b1110011
} Operation;

typedef struct {
    uint32_t op;
    uint32_t funct3;
    uint32_t funct7;
    uint32_t rd;
    uint32_t rs1;
    uint32_t rs2;
    int32_t imm_i;
    int32_t imm_s;
    int32_t imm_b;
    int32_t imm_u;
    int32_t imm_j;
} DecodedInstr;

typedef struct {
    uint32_t regs[32];
} Registers;

typedef struct {
    uint8_t *mem;
    size_t size;
} Memory;

typedef struct {
    Registers regs;
    uint32_t pc;
    Memory memory;
    size_t program_size;
} RV32ICore;

uint32_t get_bits(uint32_t value, int high, int low) {
    uint32_t mask;
    /* if you want all 32 bits */
    if (high - low + 1 == 32) {
        mask = 0xFFFFFFFF;
    } else {
        /* get high - low number of ones as a mask*/
        mask = ((1U << (high - low + 1)) - 1);
    }
    return (value >> low) & mask;
}

int32_t sign_extend(uint32_t value, int num_bits) {
    /* if there is a one in the leftmost bit (ie a negative number)
        take the 2's complement*/
    if ((value >> (num_bits - 1)) & 1) {
        return (int32_t)(value | (~((1U << num_bits) - 1)));
    } else {
        /* return the same value as inputted*/
        return (int32_t)(value & ((1U << num_bits) - 1));
    }
}

void decode_instr(uint32_t instr, DecodedInstr *decoded) {
    decoded->op = get_bits(instr, 6, 0);
    decoded->funct3 = get_bits(instr, 14, 12);
    decoded->funct7 = get_bits(instr, 31, 25);
    decoded->rd = get_bits(instr, 11, 7);
    decoded->rs1 = get_bits(instr, 19, 15);
    decoded->rs2 = get_bits(instr, 24, 20);

    /* get the bits as unsigned, then turn them into signed with sign_extend()*/
    uint32_t imm_i_raw = get_bits(instr, 31, 20);
    decoded->imm_i = sign_extend(imm_i_raw, 12);

    uint32_t imm_s_raw = (get_bits(instr, 31, 25) << 5) | get_bits(instr, 11, 7);
    decoded->imm_s = sign_extend(imm_s_raw, 12);

    /* shift the bits and | them to get them concatenated
        Example: get_bits(instr, 30, 25). Previous shift was 11.
        Now shift by 11 - (30-25+1) = 5 bits*/
    uint32_t imm_b_raw = (get_bits(instr, 31, 31) << 12) |
                         (get_bits(instr, 7, 7) << 11) |
                         (get_bits(instr, 30, 25) << 5) |
                         (get_bits(instr, 11, 8) << 1);
    decoded->imm_b = sign_extend(imm_b_raw, 13);

    uint32_t imm_u_raw = get_bits(instr, 31, 12) << 12;
    decoded->imm_u = (int32_t)imm_u_raw;

    uint32_t imm_j_raw = (get_bits(instr, 31, 31) << 20) |
                         (get_bits(instr, 19, 12) << 12) |
                         (get_bits(instr, 20, 20) << 11) |
                         (get_bits(instr, 30, 21) << 1);
    decoded->imm_j = sign_extend(imm_j_raw, 21);
}

/* set all register values to 0 
in order to make sure no errors from preloaded registers*/
void init_registers(Registers *regs) {
    for (int i = 0; i < 32; i++) {
        regs->regs[i] = 0;
    }
}

/* get register at an index */
uint32_t get_reg(Registers *regs, int index) {
    return regs->regs[index];
}

/* set register to have a value */
void set_reg(Registers *regs, int index, uint32_t value) {
    if (index != 0) {
        regs->regs[index] = value;
    }
}

/* copy predefined memory pointer into our systems memory */
void init_memory(Memory *memory, size_t size, uint8_t *initial_data, size_t initial_size) {
    memory->mem = (uint8_t *)calloc(size, sizeof(uint8_t));
    memory->size = size;
    if (initial_size > size) {
        fprintf(stderr, "Initial data size exceeds memory size\n");
        exit(1);
    }
    memcpy(memory->mem, initial_data, initial_size);
}

/* gets a byte at an address */
uint8_t read_byte(Memory *memory, uint32_t address) {
    if (address >= memory->size) {
        fprintf(stderr, "Memory read error: address out of bounds\n");
        exit(1);
    }
    return memory->mem[address];
}

/* concatenate 2 bytes to each other */
uint16_t read_halfword(Memory *memory, uint32_t address) {
    if (address + 1 >= memory->size) {
        fprintf(stderr, "Memory read error: address out of bounds\n");
        exit(1);
    }
    uint16_t value = memory->mem[address] | (memory->mem[address + 1] << 8);
    return value;
}

/* concatenate 4 bytes to each other */
uint32_t read_word(Memory *memory, uint32_t address) {
    if (address + 3 >= memory->size) {
        fprintf(stderr, "Memory read error: address out of bounds\n");
        exit(1);
    }
    uint32_t value = memory->mem[address] |
                     (memory->mem[address + 1] << 8) |
                     (memory->mem[address + 2] << 16) |
                     (memory->mem[address + 3] << 24);
    return value;
}

/* add a byte to the address specificed*/
void write_byte(Memory *memory, uint32_t address, uint8_t value) {
    if (address >= memory->size) {
        fprintf(stderr, "Memory write error: address out of bounds\n");
        exit(1);
    }
    memory->mem[address] = value;
}

/* write a byte to the address specified. Needs 2 bytes available */
void write_halfword(Memory *memory, uint32_t address, uint16_t value) {
    if (address + 1 >= memory->size) {
        fprintf(stderr, "Memory write error: address out of bounds\n");
        exit(1);
    }
    memory->mem[address] = value & 0xFF;
    memory->mem[address + 1] = (value >> 8) & 0xFF;
}

/* Writw a byte to the address specified, Needs 4 bytes available */
void write_word(Memory *memory, uint32_t address, uint32_t value) {
    if (address + 3 >= memory->size) {
        fprintf(stderr, "Memory write error: address out of bounds\n");
        exit(1);
    }
    /* bit shift each byte so that all bits are to the left */
    memory->mem[address] = value & 0xFF;
    memory->mem[address + 1] = (value >> 8) & 0xFF;
    memory->mem[address + 2] = (value >> 16) & 0xFF;
    memory->mem[address + 3] = (value >> 24) & 0xFF;
}

void execute(RV32ICore *core) {
    while (1) {
        uint32_t instr = read_word(&core->memory, core->pc);
        DecodedInstr decoded;
        decode_instr(instr, &decoded);
        
        switch (decoded.op) {
            case LUI:
                /* set register with the imm_u (it has already been shifted in decode_instr())*/
                set_reg(&core->regs, decoded.rd, decoded.imm_u);
                break;
            case AUIPC:
            /* same thing pretty much except add pc to immediate value*/
                set_reg(&core->regs, decoded.rd, core->pc + decoded.imm_u);
                break;
            case ARITH:
                /* check which function it is (funct3 is type of operation, func7 is the type)
                ex) funct3_add and funct7_alternative means subtract */
                if (decoded.funct3 == FUNCT3_ADD && decoded.funct7 == FUNCT7_DEFAULT) {
                    set_reg(&core->regs, decoded.rd, get_reg(&core->regs, decoded.rs1) + get_reg(&core->regs, decoded.rs2));
                } else if (decoded.funct3 == FUNCT3_SUB && decoded.funct7 == FUNCT7_ALTERNATIVE) {
                    set_reg(&core->regs, decoded.rd, get_reg(&core->regs, decoded.rs1) - get_reg(&core->regs, decoded.rs2));
                } else if (decoded.funct3 == FUNCT3_SLL) {
                    set_reg(&core->regs, decoded.rd, get_reg(&core->regs, decoded.rs1) << (get_reg(&core->regs, decoded.rs2) & 0x1F));
                } else if (decoded.funct3 == FUNCT3_SLT) {
                    /* set less than with signed ints */
                    int32_t rs1 = (int32_t)get_reg(&core->regs, decoded.rs1);
                    int32_t rs2 = (int32_t)get_reg(&core->regs, decoded.rs2);
                    set_reg(&core->regs, decoded.rd, rs1 < rs2 ? 1 : 0);
                } else if (decoded.funct3 == FUNCT3_SLTU) {
                    /* set less than with unsigned int */
                    uint32_t rs1 = get_reg(&core->regs, decoded.rs1);
                    uint32_t rs2 = get_reg(&core->regs, decoded.rs2);
                    set_reg(&core->regs, decoded.rd, rs1 < rs2 ? 1 : 0);
                } else if (decoded.funct3 == FUNCT3_XOR) {
                    set_reg(&core->regs, decoded.rd, get_reg(&core->regs, decoded.rs1) ^ get_reg(&core->regs, decoded.rs2));
                } else if (decoded.funct3 == FUNCT3_SRL && decoded.funct7 == FUNCT7_DEFAULT) {
                    set_reg(&core->regs, decoded.rd, get_reg(&core->regs, decoded.rs1) >> (get_reg(&core->regs, decoded.rs2) & 0x1F));
                } else if (decoded.funct3 == FUNCT3_SRA && decoded.funct7 == FUNCT7_ALTERNATIVE) {
                    int32_t rs1 = (int32_t)get_reg(&core->regs, decoded.rs1);
                    int32_t shift = get_reg(&core->regs, decoded.rs2) & 0x1F;
                    set_reg(&core->regs, decoded.rd, rs1 >> shift);
                } else if (decoded.funct3 == FUNCT3_OR) {
                    set_reg(&core->regs, decoded.rd, get_reg(&core->regs, decoded.rs1) | get_reg(&core->regs, decoded.rs2));
                } else if (decoded.funct3 == FUNCT3_AND) {
                    set_reg(&core->regs, decoded.rd, get_reg(&core->regs, decoded.rs1) & get_reg(&core->regs, decoded.rs2));
                } else {
                    fprintf(stderr, "Unknown arithmetic operation\n");
                    exit(1);
                }
                break;
            case IMM:
                if (decoded.funct3 == FUNCT3_ADDI) {
                    set_reg(&core->regs, decoded.rd, get_reg(&core->regs, decoded.rs1) + decoded.imm_i);
                } else if (decoded.funct3 == FUNCT3_SLLI) {
                    set_reg(&core->regs, decoded.rd, get_reg(&core->regs, decoded.rs1) << (decoded.imm_i & 0x1F));
                } else if (decoded.funct3 == FUNCT3_SLTI) {
                    int32_t rs1 = (int32_t)get_reg(&core->regs, decoded.rs1);
                    int32_t imm = decoded.imm_i;
                    set_reg(&core->regs, decoded.rd, rs1 < imm ? 1 : 0);
                } else if (decoded.funct3 == FUNCT3_SLTIU) {
                    uint32_t rs1 = get_reg(&core->regs, decoded.rs1);
                    uint32_t imm = (uint32_t)decoded.imm_i;
                    set_reg(&core->regs, decoded.rd, rs1 < imm ? 1 : 0);
                } else if (decoded.funct3 == FUNCT3_XORI) {
                    set_reg(&core->regs, decoded.rd, get_reg(&core->regs, decoded.rs1) ^ decoded.imm_i);
                } else if (decoded.funct3 == FUNCT3_SRLI && decoded.funct7 == FUNCT7_DEFAULT) {
                    set_reg(&core->regs, decoded.rd, get_reg(&core->regs, decoded.rs1) >> (decoded.imm_i & 0x1F));
                } else if (decoded.funct3 == FUNCT3_SRAI && decoded.funct7 == FUNCT7_ALTERNATIVE) {
                    int32_t rs1 = (int32_t)get_reg(&core->regs, decoded.rs1);
                    int32_t shift = decoded.imm_i & 0x1F;
                    set_reg(&core->regs, decoded.rd, rs1 >> shift);
                } else if (decoded.funct3 == FUNCT3_ORI) {
                    set_reg(&core->regs, decoded.rd, get_reg(&core->regs, decoded.rs1) | decoded.imm_i);
                } else if (decoded.funct3 == FUNCT3_ANDI) {
                    set_reg(&core->regs, decoded.rd, get_reg(&core->regs, decoded.rs1) & decoded.imm_i);
                } else {
                    fprintf(stderr, "Unsupported immediate instruction\n");
                    exit(1);
                }
                break;
            case SYSTEM:
                // Handle the ecall instruction
                if (decoded.funct3 == 0b000) {
                    if (decoded.imm_i == 0) {
                        // This is an ecall
                        uint32_t syscall_num = get_reg(&core->regs, 17); // x17 is a7
                        if (syscall_num == 10) {
                            // ecall 10: exit
                            // Output registers and exit
                            return;
                        } else {
                            fprintf(stderr, "Unsupported syscall number: %u\n", syscall_num);
                            exit(1);
                        }
                    } else if (decoded.imm_i == 1) {
                        // This is an ebreak
                        // Handle ebreak if needed
                        fprintf(stderr, "Encountered ebreak instruction\n");
                        exit(1);
                    } else {
                        fprintf(stderr, "Unknown SYSTEM instruction with imm_i: %u\n", decoded.imm_i);
                        exit(1);
                    }
                } else {
                    fprintf(stderr, "Unknown SYSTEM instruction with funct3: %u\n", decoded.funct3);
                    exit(1);
                }
                break;
            case BRANCH:
                if (decoded.funct3 == FUNCT3_BEQ) {
                    /* if they are equal, increment the program counter by the immediate value provided */
                    if (get_reg(&core->regs, decoded.rs1) == get_reg(&core->regs, decoded.rs2)) {
                        core->pc += decoded.imm_b;
                        continue;
                    }
                } else if (decoded.funct3 == FUNCT3_BNE) {
                    if (get_reg(&core->regs, decoded.rs1) != get_reg(&core->regs, decoded.rs2)) {
                        core->pc += decoded.imm_b;
                        continue;
                    }
                } else if (decoded.funct3 == FUNCT3_BLT) {
                    int32_t rs1 = (int32_t)get_reg(&core->regs, decoded.rs1);
                    int32_t rs2 = (int32_t)get_reg(&core->regs, decoded.rs2);
                    if (rs1 < rs2) {
                        core->pc += decoded.imm_b;
                        continue;
                    }
                } else if (decoded.funct3 == FUNCT3_BGE) {
                    int32_t rs1 = (int32_t)get_reg(&core->regs, decoded.rs1);
                    int32_t rs2 = (int32_t)get_reg(&core->regs, decoded.rs2);
                    if (rs1 >= rs2) {
                        core->pc += decoded.imm_b;
                        continue;
                    }
                } else if (decoded.funct3 == FUNCT3_BLTU) {
                    uint32_t rs1 = get_reg(&core->regs, decoded.rs1);
                    uint32_t rs2 = get_reg(&core->regs, decoded.rs2);
                    if (rs1 < rs2) {
                        core->pc += decoded.imm_b;
                        continue;
                    }
                } else if (decoded.funct3 == FUNCT3_BGEU) {
                    uint32_t rs1 = get_reg(&core->regs, decoded.rs1);
                    uint32_t rs2 = get_reg(&core->regs, decoded.rs2);
                    if (rs1 >= rs2) {
                        core->pc += decoded.imm_b;
                        continue;
                    }
                } else {
                    fprintf(stderr, "Unknown branch operation\n");
                    exit(1);
                }
                break;
            case STORE:
                if (decoded.funct3 == FUNCT3_SB) {
                    uint32_t addr = get_reg(&core->regs, decoded.rs1) + decoded.imm_s;
                    uint8_t value = get_reg(&core->regs, decoded.rs2) & 0xFF;
                    write_byte(&core->memory, addr, value);
                } else if (decoded.funct3 == FUNCT3_SH) {
                    uint32_t addr = get_reg(&core->regs, decoded.rs1) + decoded.imm_s;
                    uint16_t value = get_reg(&core->regs, decoded.rs2) & 0xFFFF;
                    write_halfword(&core->memory, addr, value);
                } else if (decoded.funct3 == FUNCT3_SW) {
                    uint32_t addr = get_reg(&core->regs, decoded.rs1) + decoded.imm_s;
                    uint32_t value = get_reg(&core->regs, decoded.rs2);
                    write_word(&core->memory, addr, value);
                } else {
                    fprintf(stderr, "Unsupported store instruction\n");
                    exit(1);
                }
                break;
            case LOAD:
                if (decoded.funct3 == FUNCT3_LB) {
                    uint32_t addr = get_reg(&core->regs, decoded.rs1) + decoded.imm_i;
                    int8_t value = (int8_t)read_byte(&core->memory, addr);
                    set_reg(&core->regs, decoded.rd, (int32_t)value);
                } else if (decoded.funct3 == FUNCT3_LH) {
                    uint32_t addr = get_reg(&core->regs, decoded.rs1) + decoded.imm_i;
                    int16_t value = (int16_t)read_halfword(&core->memory, addr);
                    set_reg(&core->regs, decoded.rd, (int32_t)value);
                } else if (decoded.funct3 == FUNCT3_LW) {
                    uint32_t addr = get_reg(&core->regs, decoded.rs1) + decoded.imm_i;
                    int32_t value = (int32_t)read_word(&core->memory, addr);
                    set_reg(&core->regs, decoded.rd, value);
                } else if (decoded.funct3 == FUNCT3_LBU) {
                    uint32_t addr = get_reg(&core->regs, decoded.rs1) + decoded.imm_i;
                    uint8_t value = read_byte(&core->memory, addr);
                    set_reg(&core->regs, decoded.rd, (uint32_t)value);
                } else if (decoded.funct3 == FUNCT3_LHU) {
                    uint32_t addr = get_reg(&core->regs, decoded.rs1) + decoded.imm_i;
                    uint16_t value = read_halfword(&core->memory, addr);
                    set_reg(&core->regs, decoded.rd, (uint32_t)value);
                } else {
                    fprintf(stderr, "Unsupported load instruction\n");
                    exit(1);
                }
                break;
            case JAL:
                set_reg(&core->regs, decoded.rd, core->pc + 4);
                core->pc += decoded.imm_j;
                continue;
            case JALR:
                set_reg(&core->regs, decoded.rd, core->pc + 4);
                core->pc = (get_reg(&core->regs, decoded.rs1) + decoded.imm_i) & ~1;
                continue;
            default:
                fprintf(stderr, "Unknown operation %d\n", decoded.op);
                exit(1);
        }
        /* increment 4 because that is what each instruction takes up */
        core->pc += 4;
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: ./sim <tests path>\n");
        return 1;
    }

    char *tests_path = argv[1];

    char *tasks[] = {"task1", "task2", "task3", "task4"};
    int num_tasks = 4;

    for (int t = 0; t < num_tasks; t++) {
        printf("================ %s ================\n", tasks[t]);

        // Build task path
        char task_path[1024];
        snprintf(task_path, sizeof(task_path), "%s/%s", tests_path, tasks[t]);

        // Open directory
        DIR *dir = opendir(task_path);
        if (dir == NULL) {
            perror("opendir");
            continue;
        }

        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL) {
            char *filename = entry->d_name;
            // Check if filename ends with ".bin"
            if (strstr(filename, ".bin") != NULL && strcmp(filename + strlen(filename) - 4, ".bin") == 0) {
                // Process the file
                printf("%s ", filename);
                int padding = 16 - strlen(filename);
                for (int i = 0; i < padding; i++) printf(" ");

                // Build full file path
                char filepath[1024];
                snprintf(filepath, sizeof(filepath), "%s/%s", task_path, filename);

                // Read the program from the .bin file
                FILE *program_file = fopen(filepath, "rb");
                if (program_file == NULL) {
                    perror("fopen");
                    continue;
                }

                // Read the file into buffer
                fseek(program_file, 0, SEEK_END);
                size_t program_size = ftell(program_file);
                rewind(program_file);
                uint8_t *program = (uint8_t *)malloc(program_size);
                fread(program, 1, program_size, program_file);
                fclose(program_file);

                // Initialize the core
                RV32ICore core;
                init_registers(&core.regs);
                core.pc = 0;
                init_memory(&core.memory, 0x100000, program, program_size); // 1MB memory
                core.program_size = program_size;
                
                // Execute the core
                execute(&core);

                // Collect output
                uint8_t output[32 * 4];
                for (int i = 0; i < 32; i++) {
                    uint32_t reg_value = get_reg(&core.regs, i);
                    output[i * 4] = reg_value & 0xFF;
                    output[i * 4 + 1] = (reg_value >> 8) & 0xFF;
                    output[i * 4 + 2] = (reg_value >> 16) & 0xFF;
                    output[i * 4 + 3] = (reg_value >> 24) & 0xFF;
                }

                // Read expected result from .res file
                char res_filename[1024];
                strncpy(res_filename, filename, sizeof(res_filename));
                res_filename[strlen(res_filename) - 4] = '\0'; // Remove ".bin"
                strcat(res_filename, ".res");
                char res_filepath[1024];
                snprintf(res_filepath, sizeof(res_filepath), "%s/%s", task_path, res_filename);

                FILE *res_file = fopen(res_filepath, "rb");
                if (res_file == NULL) {
                    perror("fopen");
                    continue;
                }

                // Read the expected result
                fseek(res_file, 0, SEEK_END);
                size_t res_size = ftell(res_file);
                rewind(res_file);
                uint8_t *result = (uint8_t *)malloc(res_size);
                fread(result, 1, res_size, res_file);
                fclose(res_file);

                // Compare output with result
                int passed = 1;
                size_t min_size = (32 * 4 < res_size) ? (32 * 4) : res_size;
                if (memcmp(output, result, min_size) != 0) {
                    passed = 0;
                }

                if (passed) {
                    printf("PASSED\n");
                } else {
                    printf("FAILED\n");
                    printf("Got:\n");
                    for (size_t i = 0; i < 32 * 4; i++) {
                        printf("%02x", output[i]);
                    }
                    printf("\nExpected:\n");
                    for (size_t i = 0; i < res_size; i++) {
                        printf("%02x", result[i]);
                    }
                    printf("\n");
                }

                // Free resources
                free(program);
                free(result);
                free(core.memory.mem);

            }
        }
        closedir(dir);
    }

    return 0;
}
