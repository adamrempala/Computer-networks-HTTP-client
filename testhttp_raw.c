#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include <stdarg.h>
#include <string.h>

#define HEADERTITLE 200
#define ADDR_SIZE 5000
#define MAX_COOKIE_FILE_SIZE 1800000
#define MAX_REQUEST_SIZE 1820000

void lower200(char* input, char* output) {
    size_t i = 0;
    while (input[i] != '\0' && i < HEADERTITLE) {
        
        if (input[i] >= 65 && input[i] <= 90) {
            output[i] = input[i] + 32;
        } else {
            output[i] = input[i];
        }
        
        i++;
    }
    output[i] = '\0';
}

void syserr(const char *fmt, ...)
{
  va_list fmt_args;
  int err;

  fprintf(stderr, "ERROR: ");
  err = errno;

  va_start(fmt_args, fmt);
  vfprintf(stderr, fmt, fmt_args);
  va_end(fmt_args);
  fprintf(stderr, " (%d; %s)\n", err, strerror(err));
  exit(EXIT_FAILURE);
}

// komunikat błędu
void fatal(const char *fmt, ...)
{
  va_list fmt_args;

  fprintf(stderr, "ERROR: ");
  va_start(fmt_args, fmt);
  vfprintf(stderr, fmt, fmt_args);
  va_end(fmt_args);
  fprintf(stderr, "\n");
  exit(EXIT_FAILURE);
}

// zwraca liczbę w post. dzies. albo -1 jeżeli wejście nie jest w postaci szesn.
int isHexNumber (char* line) {
  size_t i = 0;
  int number = 0;
  
  // Wejście powinno być liczbą i kończyć się CR\0 (podajemy linie).
  while (line[i] != '\r' && line[i] != '\0') {
    number *= 16;
    
    if (line[i] >= 48 && line[i] <= 57)
      number += line[i] - 48;
    else if (line[i] >= 97 && line[i] <= 102)
      number += line[i] - 87;
    else {
      return -1; // w przypadku znaku, który nie jest hex-cyfrą
    }
    i++;
  }
  
  if (i == 0 || line[i] != '\r' || line[i+1] != '\0')
      return -1; // w przypadku nieprawidłowego zakończenia
  
  return number;
}

// Dostając odpowiedź 200 OK, tworzy raport ciasteszek i długości zasobu
void create_report(char* response, size_t length) {
  
  size_t line_size = ADDR_SIZE;
  char* line = malloc(line_size), lower[HEADERTITLE + 1];
  
  if (line == NULL) {
    free(response);
    fatal("Line alocation error");
  }
  
  size_t i = 0, li = 0;
  int clen = 0, hexer = 0, to_end_of_chunk = 0;
  bool is_chunked = false, message_body = false;
  
  while (length > 0) {
    // powiększamy tablicę do zaczytywania linii, jeśli trzeba
    if (i >=  line_size - 2) { 
      line_size *= 2;
      line = realloc(line, line_size);
      if (line == NULL) {
        free(response);
        fatal("Line realocation error");
      }
    }
    if (response[i] != '\n') {
      line[li] = response[i];
      i++;
      li++;
    } else {
      line[li] = '\0';
      li++;
      i++;      
      // kolejna linia zaczytana
      lower200(line, lower);
      if (!message_body && !strncmp(lower, "content-length: ", 16)) { // gdy mamy długość zasobu
        clen = (int)strtol(line+16, NULL, 10);
        clen = 0;
        is_chunked = false;
      } else if (!message_body && !strncmp(lower, "set-cookie: ", 12)) {  // gdy mamy ciasteczko
        size_t lc = 12;
        
        while (line[lc] != ';' && line[lc] != '\r') {
          if (line[lc] == '\0') {
            free(line);
            free(response);
            fatal("There should be no 0-ascii in cookie");
          }
          
          lc++;
        }
        
        line[lc] = '\0';
        printf("%s\n", line+12); // wypisanie ciasteczka na wyjście
      } else if (!message_body && !strncmp(lower, "transfer-encoding: chunked", 26)) {
        is_chunked = true; // włączamy tryb śledzenia długości chunków
        clen = 0;
      } else if (strlen(line) + 1 == li && message_body && is_chunked && to_end_of_chunk == 0 && (hexer = isHexNumber(line)) >= 0) {
        clen -= 2; // odjęcie znaków /r/n na końcu chunka, który zaczytujemy
        to_end_of_chunk = hexer + 2;
      } else {
        if (message_body == true) {
          clen += li; // linia wlicza się do zawartości
          to_end_of_chunk -= li;
          if (li < 0) {
            free(line);
            free(response);
            fatal("Chunk length disonance");
          }
        } else if (li == 2) {
          message_body = true; // odtąd zaczyna się zawartość (content)
        }
      }
      li = 0;
    }
    length--;
  }
  
  printf("Dlugosc zasobu: %d\n", clen); // wypisanie sumy długości zasobów
  free(line);
}

// dostając adres pliku, wypisuje do stringa output listę ciasteczek do wysłania
void convert_cookies(char* filename, char* output) {
  char fileshot[MAX_COOKIE_FILE_SIZE]; // tu będziemy wczytywać plik ciasteczek
  FILE *f = fopen(filename, "r"); // otwarcie pliku
  
  if (f == NULL)
      syserr("File did not open, maybe it does not exist");
  
  size_t hmr = 0, red = 0; // ile w pojedynczym wczytaniu wczytano bajtów

  while ((hmr = fread(fileshot + red, 1, sizeof(fileshot) - 1 - red, f)) != 0) {
    if (hmr < 0)
      fatal("Reading form file fail");
    
    red += hmr;
  }

  fileshot[red] = '\0';
  fclose(f); // zamknięcie pliku

  size_t inf = 0, ino = 0;

  while (fileshot[inf] != '\0') {
    if (fileshot[inf] != '\n') {
      output[ino] = fileshot[inf];
    } else if (fileshot[inf + 1] != '\0'){
      output[ino] = ';';
      output[ino+1] = ' ';
      ino++;
    }

    ino++;
    inf++;
  }
  output[ino] = '\0';
}

// zczytuje z argumentu adres i port do połączenia
int get_address_and_port(char* withcl, char* address) {

  char* x = NULL;
  size_t a = 0, b = strlen(withcl) - 1;

  // szukanie ostatniego dwukropka
  while(withcl[b] != ':' && b != 0) {
    b--;
  }

  if (b == 0)
    fatal("No port"); // błąd, kiedy w adr. nie ma dwukropka przed portem

  // początek adresu jest taki sam, jak argumentu
  while(a != b) {
    if (withcl[a] == ':' || withcl[a] == '/' || withcl[a] == '\\')
      fatal("Invalid sign in address");
    
    address[a] = withcl[a];
    a++;
  }
  
  address[a] = '\0';
  a++;

  // withcl+a to adres początku numeru portu
  int port = (int)strtol(withcl+a, &x, 10);

  // od x-a oczekujemy, że będzie adresem końca wejścia
  if (x != withcl+strlen(withcl)) {
    fatal("Invalid port name");
  }

  return port; // adres jest w address, numer portu na wyjściu
}

// zapisuje
void get_test_address_and_res(const char* input, char* address,
                              char* resource, bool* is_s) {

  int red = 0;
  size_t a = 0;

  // ustalamy protokół
  if (!strncmp(input, "http://", 7)) {
    red = 7;
    *is_s = false;
  } else if (!strncmp(input, "https://", 8)) {
    red = 8;
    *is_s = true;
  } else {
    fatal("Invalid protocol");
  }

  // adres domeny, z której pobieramy zasób
  while(input[a + red] != '\0') {
    if (input[a + red] == '/')
      break;

    address[a] = input[a + red];

    a++;
  }
  
  if (a > 0 && address[a-1] == ':')
    address[a - 1] = '\0';
  else
    address[a] = '\0';
  
  int i = 0;

  // zasób, który pobieramy
  if (input[a + red] == '/') {

    while (input[a + i + red] != '\0') {
      resource[i] = input[a + i + red];
      i++;
    }

  } else {
    resource[0] = '/';
    resource[1] = '\0';
  }
}

int main(int argc, char *argv[]) {
  
  // test liczby parametrów
  if (argc != 4) {
    fatal("Invalid number of arguments");
  }

  char address[ADDR_SIZE], port_str[ADDR_SIZE], request[MAX_REQUEST_SIZE],
    test_adr[ADDR_SIZE], test_res[ADDR_SIZE], cookies[MAX_COOKIE_FILE_SIZE];
  bool httpsbool;

  // pobieramy adres i port połączenia
  int port_num = get_address_and_port(argv[1], address);
  
  // pobieramy dane dot. zasobu
  get_test_address_and_res(argv[3], test_adr, test_res, &httpsbool);
  
  // tworzymy string o ciasteczkach
  convert_cookies(argv[2], cookies);
  
  // port również będzie w stringu
  sprintf(port_str, "%d", port_num);

  struct addrinfo addr_hints, *addr_result;

  // utworzenie gniazda
  int sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

  if (sock < 0) {
    syserr("Socket error");
  }

  // trzeba się dowiedzieć o adresie internetowym serwera
  memset(&addr_hints, 0, sizeof(struct addrinfo));
  addr_hints.ai_flags = 0;
  addr_hints.ai_family = AF_INET;
  addr_hints.ai_socktype = SOCK_STREAM;
  addr_hints.ai_protocol = IPPROTO_TCP;

  if (getaddrinfo(address, port_str, &addr_hints, &addr_result) != 0) {
    fatal("Address info error");
  }

  // łączymy z serwerem
  if (connect(sock, addr_result->ai_addr, addr_result->ai_addrlen) != 0) {
    syserr("Connection error");
  }

  freeaddrinfo(addr_result);

  // wysyłamy odpowiednie żądanie, w zależności od tego, czy wysyłamy ciasteczka
  memset(request, 0, sizeof(request));
  if (strlen(cookies) > 0)
    sprintf(request, "GET %s HTTP/1.1\r\nHost: %s\r\nCookie: %s\r\nConnection: close\r\n\r\n",
      test_res, test_adr, cookies);
  else
    sprintf(request, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
      test_res, test_adr);
  
    //printf("%s\n", request);
  // wysyłamy żądanie do serwera
  size_t wrt = 0;
  int howmanywritten = 0;

  while ((howmanywritten = write(sock, request+wrt, strlen(request))-wrt) != 0) {
    if (howmanywritten < 0)
      syserr("Writing to socket fail");
    
    wrt += howmanywritten;
  }
  
  size_t rsi = 0;
  int red = 0;
  //robimy miejsce na odpowiedź
  char* responder = (char*)malloc(rsi + ADDR_SIZE);
  if (responder == NULL)
      fatal("Memory alocation error");
  
  // wczytujemy odpowiedź
  while ((red = read(sock, responder + rsi, ADDR_SIZE)) != 0) {
    if (red < 0) {
      free(responder);
      syserr("Reading from stream socket failed");
    }
    rsi += red;
    responder = (char*)realloc(responder, rsi + ADDR_SIZE);
    if (responder == NULL)
        fatal("Memory realocation error");
  }
  responder[rsi] = '\0';
  
  if (close(sock) < 0) {
    free(responder);
    fatal("Closing stream socket failed");
  }
  if (strncmp(responder, "HTTP/1.1 200 OK", 15) != 0) { // przypadek nie 200 OK
    int i = 0;
    while (responder[i] != '\r' && responder[i] != '\n' && i < rsi) {
      i++;
    }
    responder[i] = '\0';
    
    printf("%s\n", responder);
  } else {  // przypadek 200 OK
    create_report(responder, rsi);
  }
  free(responder);
  return 0;
}
